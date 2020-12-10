#include "trace.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>

#include "util.h"

struct syscall_info {
    uint64_t id;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
};

void get_registers(pid_t ch, struct user_regs_struct *regs) {
    ptrace(PTRACE_GETREGS, ch, NULL, regs);
}

void set_registers(pid_t ch, struct user_regs_struct *regs) {
    ptrace(PTRACE_SETREGS, ch, NULL, regs);
}

/** Mapping registers to syscall params */
void parse_syscall_params(const struct user_regs_struct *regs, struct syscall_info *out) {
    out->id   = regs->orig_rax;
    out->arg1 = regs->rdi;
    out->arg2 = regs->rsi;
    out->arg3 = regs->rdx;
    out->arg4 = regs->r10;
    out->arg5 = regs->r8;
    out->arg6 = regs->r9;
}

/** Get process memory using Linux proc filesystem */
char *get_mem_str(pid_t pid, uint64_t addr) {
    char buf[PATH_MAX];
    sprintf(buf, "/proc/%d/mem", pid);
    FILE *fp = fopen(buf, "r");
    if (fp == NULL) {
        fprintf(stderr, "Open %s failed.\n", buf);
        return "";
    }
    fseek(fp, addr, SEEK_SET);
    int i = 0;
    while (1) {
        buf[i] = fgetc(fp);
        if (buf[i] == 0 || i >= PATH_MAX || feof(fp))
            break;
        i++;
    }
    fclose(fp);
    char *p = malloc(sizeof(char) * (i + 1));
    memcpy(p, buf, sizeof(char) * (i + 1));
    return p;
}

/** Check syscall and its argument */
void on_syscall(pid_t pid, int type) {
    struct user_regs_struct regs;
    struct syscall_info info;

    get_registers(pid, &regs);

    if (type == 0) {
        parse_syscall_params(&regs, &info);
        char *pathname;
        int fd;
        uint64_t flags, mode;
        switch (info.id) {
        case SYS_execve:
            if (info.arg1 != 0) {
                pathname = get_mem_str(pid, info.arg1);
                printf("Syscall execve pathname: %s\n", pathname);
                if (strcmp(pathname, "/bin/sh") == 0 || strcmp(pathname, "/bin/bash") == 0 || strcmp(pathname, "/bin/dash") == 0 || strcmp(pathname, "/bin/zsh") == 0) {
                    printf("{\"type\": \"detected potential backdoor\", \"extra\": \"execve %s\"}", pathname);
                    regs.orig_rax = -1;
                    set_registers(pid, &regs);
                    kill(-pid, SIGTERM);
                    kill(-pid, SIGKILL);
                    exit(10);
                }
                free(pathname);
            }
            break;
        case SYS_execveat:
            pathname = get_mem_str(pid, info.arg2);
            printf("Syscall execveat pathname: %s\n", pathname);
            free(pathname);
            break;
        case SYS_open:
            pathname = get_mem_str(pid, info.arg1);
            flags = info.arg2;
            mode = info.arg3;
            printf("Syscall open pathname: %s, flags: %lu, mode: %lu\n", pathname, flags, mode);

            /* check for open passwd */
            // if (strcmp(pathname, "/etc/passwd") == 0) {
            //     printf("{\"type\": \"detected access to /etc/passwd\", \"extra\": \"open %s\"}", pathname);
            //     regs.orig_rax = -1;
            //     set_registers(pid, &regs);
            //     kill(-pid, SIGTERM);
            //     kill(-pid, SIGKILL);
            //     exit(10);
            // }
            /* check for access crontab */
            if (strcmp(pathname, "/etc/crontab") == 0) {
                printf("{\"type\": \"detected access to /etc/crontab\", \"extra\": \"open %s\"}", pathname);
                regs.orig_rax = -1;
                set_registers(pid, &regs);
                kill(-pid, SIGTERM);
                kill(-pid, SIGKILL);
                exit(10);
            }
            if (starts_with(pathname, "/etc/cron.d/")) {
                printf("{\"type\": \"detected access to file under /etc/cron.d/\", \"extra\": \"open %s\"}", pathname);
                regs.orig_rax = -1;
                set_registers(pid, &regs);
                kill(-pid, SIGTERM);
                kill(-pid, SIGKILL);
                exit(10);
            }

            free(pathname);
            break;
        case SYS_openat:
            fd = info.arg1;
            pathname = get_mem_str(pid, info.arg2);
            flags = info.arg3;
            mode = info.arg4;
            printf("Syscall openat pathname: %s, flags: %lu, mode: %lu", pathname, flags, mode);
            if (fd == AT_FDCWD)
                printf(", fd is cwd");
            putchar('\n');

            /* Check for open passwd */
            // if (strcmp(pathname, "/etc/passwd") == 0) {
            //     printf("{\"type\": \"detected access to /etc/passwd\", \"extra\": \"openat %s\"}", pathname);
            //     regs.orig_rax = -1;
            //     set_registers(pid, &regs);
            //     kill(-pid, SIGTERM);
            //     kill(-pid, SIGKILL);
            //     exit(10);
            // }
            /* Check for access crontab */
            if (strcmp(pathname, "/etc/crontab") == 0) {
                printf("{\"type\": \"detected access to /etc/crontab\", \"extra\": \"openat %s\"}", pathname);
                regs.orig_rax = -1;
                set_registers(pid, &regs);
                kill(-pid, SIGTERM);
                kill(-pid, SIGKILL);
                exit(10);
            }
            if (starts_with(pathname, "/etc/cron.d/")) {
                printf("{\"type\": \"detected access to file under /etc/cron.d/\", \"extra\": \"openat %s\"}", pathname);
                regs.orig_rax = -1;
                set_registers(pid, &regs);
                kill(-pid, SIGTERM);
                kill(-pid, SIGKILL);
                exit(10);
            }

            free(pathname);
            break;
        }
    }
}

/** Set ptrace traceme */
void setup_trace() {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    // kill(getpid(), SIGSTOP);
}

/** Use ptrace to trace syscall */
void trace_loop() {
    int insyscall = 0; // 表示当前是进入还是退出 syscall
    int options_enabled = 0; // 标识是否开启 PTRACE_O_TRACESYSGOOD，开启时获取到的 stopsig 为 SIGTRAP | 0x80，表示是 syscall 造成的 stop
    while (1) {
        int status;
        pid_t child = waitpid((pid_t)(-1), &status, __WALL);
        if (errno == ECHILD) {
            errno = 0;
            break;
        }
        int stopsig = WSTOPSIG(status);
        siginfo_t sig;

        int syscallstop = 0;
        if (options_enabled && stopsig == (SIGTRAP | 0x80)) // PTRACE_O_TRACESYSGOOD 开启时，syscall stop 对应信号为 SIGTRAP | 0x80
            syscallstop = 1;
        if (!options_enabled && stopsig == (SIGTRAP)) { // 未开始上述选项时，信号为 SIGTRAP
            ptrace(PTRACE_GETSIGINFO, child, 0, &sig);
            syscallstop = (sig.si_code == SIGTRAP || sig.si_code == (SIGTRAP | 0x80));
        }
        if (syscallstop) {
            on_syscall(child, insyscall), insyscall = !insyscall; // 处理 syscall
            if (!options_enabled) {
                ptrace(PTRACE_SETOPTIONS, child, NULL,
                    PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
                options_enabled = 1;
            }
        }
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
}

/** Check process fds */
static char* agent_file_check(DIR* dir, char* pid) {
    struct dirent *ent;
    char buf[PATH_MAX];
    while (1)
    {
        ent = readdir(dir);
        char* target;
        if (ent == NULL)
            break;
        if (is_numeric(ent->d_name)) {
            sprintf(buf, "/proc/%s/fd/%s", pid, ent->d_name);
            target = read_link_path(buf);
            // printf("%s -> %s\n", buf, target);
            /* check for open passwd */
            // if (strcmp(target, "/etc/passwd") == 0) {
            //     return target;
            // }
            /* check for access crontab */
            if (strcmp(target, "/etc/crontab") == 0) {
                return target;
            }
            if (starts_with(target, "/etc/cron.d/")) {
                return target;
            }
            free(target);
        }
    }
    return NULL;
}

/** Observe process behavior to assist tracing */
void agent_loop(pid_t pid) {
    char buf[PATH_MAX];
    while (1) {
        DIR *dir;
        struct dirent *ent;
        dir = opendir("/proc");
        int proc_count = 0;
        if (dir != NULL) {
            while (1) {
                ent = readdir(dir);
                if (ent == NULL)
                    break;
                if (is_numeric(ent->d_name)) { // 如果是数字，则是进程目录
                    proc_count++;
                    /* Check suspicious launching cmdline */
                    sprintf(buf, "/proc/%s/cmdline", ent->d_name);
                    FILE *fp = fopen(buf, "r");
                    fgets(buf, PATH_MAX - 1, fp);
                    fclose(fp);
                    if (strcmp(buf, "/bin/sh") == 0 || strcmp(buf, "/bin/bash") == 0 || strcmp(buf, "/bin/dash") == 0 || strcmp(buf, "/bin/zsh") == 0) {
                        printf("{\"type\": \"detected potential backdoor\", \"extra\": \"process cmdline %s\"}", buf);
                        kill(-1, SIGTERM);
                        kill(-1, SIGKILL);
                        exit(10);
                    }

                    /* Check suspicious file opens */
                    sprintf(buf, "/proc/%s/fd", ent->d_name);
                    DIR *dir_fd = opendir(buf);
                    if (dir_fd != NULL) {
                        char* fd_path;
                        fd_path = agent_file_check(dir_fd, ent->d_name);
                        if (fd_path != NULL) {
                            printf("{\"type\": \"detected access to sensitive file\", \"extra\": \"fd opened for %s\"}", fd_path);
                            free(fd_path);
                            kill(-1, SIGTERM);
                            kill(-1, SIGKILL);
                            exit(10);
                        }
                    }
                    closedir(dir_fd);
                }
            }
        }
        closedir(dir);
        if (proc_count <= 2) {
            break;
        }
        usleep(1000 * 200);
    }
}
