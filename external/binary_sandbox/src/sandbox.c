#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <errno.h>

#include "mkroot.h"
#include "util.h"
#include "dependency.h"
#include "trace.h"

#define CONTAINER_STACK_SIZE (1024 * 1024)

static char container_stack[CONTAINER_STACK_SIZE];

int container_pid;
char *container_cwd;
char **container_execv_args;

char *debug_container_execv_args[] = {
    "/bin/sh",
    NULL
};

int container_main(void *run_as) {
    // printf("Container PID: %d\n", getpid());
    /** Remount / to private mode (IMPORTANT) */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        perror("Failed to remount / to private");
    }
    /** Mount functional directories */
    if (mount("proc", "rootfs/proc", "proc", 0, NULL) != 0) {
        perror("Failed to mount proc");
    }
    if (mount("sysfs", "rootfs/sys", "sysfs", 0, NULL) != 0) {
        perror("Failed to mount sys");
    }
    if (mount("none", "rootfs/tmp", "tmpfs", 0, NULL) != 0) {
        perror("Failed to mount tmp");
    }
    if (mount("tmpfs", "rootfs/run", "tmpfs", 0, NULL) != 0) {
        perror("Failed to mount run");
    }
    /** Change root */
    if (chdir("./rootfs") != 0 || chroot("./") != 0){
        perror("Failed to chroot");
    }

    /** Change cwd */
    chdir(container_cwd);
    /** Set env */
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);

    /** Change user */
    if (run_as != NULL) {
        struct passwd *pw;
        if ((pw = getpwnam((char*)run_as)) == NULL) {
            fprintf(stderr, "No such user %s", (char*)run_as);
            return -1;
        }
        if (setgid(pw->pw_gid) != 0) {
            fprintf(stderr, "Failed to setgid to %d", pw->pw_gid);
        }
        if (setuid(pw->pw_uid) != 0) {
            fprintf(stderr, "Failed to setuid to %d", pw->pw_uid);
        }
    }

    /** Setup ptrace */
    pid_t pid = fork();
    pid_t pid_agent;
    switch (pid) {
    case -1:
        fprintf(stderr, "Failed to fork");
        break;
    case 0:
        setup_trace();
        /** Execute target */
        execv(container_execv_args[0], container_execv_args);
    default:
        pid_agent = fork();
        switch (pid_agent) {
        case 0:
            agent_loop(pid);
            break;
        default:
            trace_loop();
            break;
        }
        break;
    }

    // execv(debug_container_execv_args[0], debug_container_execv_args);

    return 0;
}

int precheck(const char *filename) {
    if (access(filename, F_OK) != 0) {
        printf("{ \"type\": \"no such file\", \"extra\": \"%s\" }", filename);
        return -1;
    }
    char content[128];
    if (!is_elf_file(filename)) {
        printf("{ \"type\": \"file is not an ELF file\", \"extra\": \"%s\" }", filename);
        return -1;
    }
    if (get_section(content, filename, ".interp") != 0) // The program may be a go application
        return 0;
    if (strcmp(content, "/lib64/ld-linux-x86-64.so.2") != 0) {
        printf("{ \"type\": \"invalid linker\", \"extra\": \"%s\" }", content);
        return -1;
    }
    return 0;
}

void terminate_sandbox(int sig) {
    if (container_pid != 0) {
        kill(-container_pid, SIGTERM);
        kill(-container_pid, SIGKILL);
    }
    exit(-3);
}

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        fprintf(stderr, "Please give a program and its argument");
        return -1;
    }
    if (precheck(argv[1]) != 0)
        return 1;
    container_execv_args = malloc(sizeof(char*) * argc);
    container_execv_args[argc - 1] = NULL;
    for (int i = 0; i < argc - 1; ++i) {
        int len = strlen(argv[i + 1]);
        container_execv_args[i] = malloc(sizeof(char) * (len + 1));
        memcpy(container_execv_args[i], argv[i + 1], sizeof(char) * (len + 1));
    }
    // printf("Parent PID: %d\n", getpid());
    if (access("./rootfs", F_OK) == 0)
        system("rm -rf ./rootfs");
    mkdir("./rootfs", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    /** Make root */
    mkroot("./rootfs");
    /** Setup conf files */
    copy_file("/etc/hostname", "./rootfs/etc/hostname");
    copy_file("/etc/passwd", "./rootfs/etc/passwd");
    copy_file("/etc/group", "./rootfs/etc/group");
    copy_file("/etc/hosts", "./rootfs/etc/hosts");
    copy_file("/etc/resolv.conf", "./rootfs/etc/resolv.conf");
    copy_file("/etc/nsswitch.conf", "./rootfs/etc/nsswitch.conf");
    /** Make program directory */
    char path[PATH_MAX];
    char *dup_program = strdup(argv[1]);
    if (dup_program[0] != '/') {
        char *cwd = malloc(sizeof(char) * PATH_MAX);
        getcwd(cwd, PATH_MAX);
        path_join(path, 3, "./rootfs", cwd, dirname(dup_program));
        free(cwd); cwd = NULL;
    }
    else
        path_join(path, 2, "./rootfs", dirname(dup_program));
    mkdir_recursively(path, S_IRWXU | S_IRWXG | S_IRWXO);
    /** Set cwd */
    char *value = getenv("SANDBOX_CWD");
    if (value == NULL) {
        int len = strlen(dup_program);
        container_cwd = malloc(sizeof(char) * (len + 1));
        memcpy(container_cwd, dup_program, sizeof(char) * (len + 1));
    } else {
        int len = strlen(value);
        container_cwd = malloc(sizeof(char) * (len + 1));
        memcpy(container_cwd, value, sizeof(char) * (len + 1));
        free(value);
    }
    free(dup_program);
    /** Copy program and its dependency */
    dup_program = strdup(argv[1]);
    path_join(path, 2, path, basename(dup_program));
    copy_file(argv[1], path);
    free(dup_program); dup_program = NULL;
    copy_dependencies("./rootfs", argv[1]);
    /** Get run user */
    value = getenv("SANDBOX_USER");
    if (value == NULL)
        value = getlogin();
    /** Start sandbox */
    signal(SIGINT, terminate_sandbox);
    container_pid = clone(container_main, container_stack + CONTAINER_STACK_SIZE, CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, value);
    waitpid(container_pid, NULL, 0);
}
