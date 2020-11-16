#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <errno.h>
#include <stddef.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#define DLOPEN_FAILED 121
#define BANNED 4095

#ifndef ARCH_32
#define LIBC_PATH "/lib/x86_64-linux-gnu/libc.so.6"
#else
#define LIBC_PATH "/lib32/libc.so.6"
#endif

void init_sandbox()
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ, 59, 2, 1),
        BPF_JUMP(BPF_JMP | BPF_JEQ, 11, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (BANNED & SECCOMP_RET_DATA)),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    // scmp_filter_ctx ctx;
	// ctx = seccomp_init(SCMP_ACT_ALLOW);
	// seccomp_rule_add(ctx, SCMP_ACT_ERRNO(BANNED), SCMP_SYS(execve), 0);
	// seccomp_load(ctx);
}

int (*real_main)(int, char **, char **);

int wrapper_main(int __argc, char **__argv, char **__envp) {
    init_sandbox();
    int ret = real_main(__argc, __argv, __envp);
    if (errno == BANNED)
        printf("Detected execve syscall! Banned!");
    return ret;
}

int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **ubp_av,
    void (*init)(void),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void(*stack_end))
{
    real_main = main;
    int (*real_libc_start_main)(
        int (*main)(int, char **, char **),
        int argc,
        char **ubp_av,
        void (*init)(void),
        void (*fini)(void),
        void (*rtld_fini)(void),
        void(*stack_end));
    void *libc_handle = dlopen(LIBC_PATH, RTLD_LOCAL | RTLD_LAZY);
    if (libc_handle == NULL)
    {
        _exit(DLOPEN_FAILED);
    }
    *(void **)(&real_libc_start_main) = dlsym(libc_handle, "__libc_start_main");
    return real_libc_start_main(wrapper_main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
