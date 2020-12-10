#include "mkroot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "util.h"
#include "dependency.h"

const int root_directories_length = 16;
const char *root_directories[] = {
    "bin", "dev", "etc", "home", "lib", "lib64", "mnt", "opt", "proc", "root", "run", "sbin", "sys", "tmp", "usr", "var"
};

const int copy_binaries_count = 4;
const int copy_binaries_length[] = {40, 14, 1, 3};
const char *copy_binaries_directories[] = { "/bin", "/usr/bin", "/sbin", "/" };

const char *bin_list[] = { "bash", "cat", "chgrp", "chmod", "chown", "cp", "echo", "grep", "gzip", "hostname", "ip", "kill", "less", "ln", "ls", "more", "mount", "mountpoint", "mv", "ping", "ps", "pwd", "rm", "sed", "sh", "sleep", "tac", "tail", "tar", "tee", "test", "toe", "top", "touch", "tr", "truncate", "tty", "umount", "uname", "which" };
const char *usr_bin_list[] = { "curl", "env", "id", "strace", "tac", "tail", "tee", "test", "toe", "top", "tr", "truncate", "tty", "whoami" };
const char *sbin_list[] = { "ifconfig" };
const char *extra_list[] = { "/lib/x86_64-linux-gnu/libnss_compat.so.2", "/lib/x86_64-linux-gnu/libnss_files.so.2", "/lib/x86_64-linux-gnu/libnss_dns.so.2" };

const char **copy_binaries_list[] = {
    bin_list,
    usr_bin_list,
    sbin_list,
    extra_list
};

/** Copy path_bin's dependencies to root */
void copy_dependencies(const char *root, const char *path_bin) {
    char content[128], *dependencies[128], path[PATH_MAX];
    if (get_section(content, path_bin, ".interp") != 0)
        return;
    assert(strcmp(content, "/lib64/ld-linux-x86-64.so.2") == 0);
    int n = get_dependencies(dependencies, path_bin);
    for (int i = 0; i < n; ++i) {
        if (strcmp(dependencies[i], "linux-vdso.so.1") == 0) continue;
        char *dup_dependency = strdup(dependencies[i]);
        path_join(path, 2, root, dirname(dup_dependency));
        free(dup_dependency);
        dup_dependency = NULL;
        if (access(path, F_OK) != 0)
            mkdir_recursively(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        path_join(path, 2, root, dependencies[i]);
        if (access(path, F_OK) != 0) {
            // printf("Copying %s's dependency from %s to %s\n", path_bin, dependencies[j], path);
            if (copy_file(dependencies[i], path) != 0) {
                fprintf(stderr, "Failed to copy dependency from %s to %s\n", dependencies[i], path);
            }
        }
        free(dependencies[i]);
        dependencies[i] = NULL;
    }
}

/** Make fake root */
int mkroot(const char *root) {
    char path[PATH_MAX], path_bin[PATH_MAX];
    if (is_directory_empty(root) != 0) {
        fprintf(stderr, "Directory %s is not empty\n", root);
        return -1;
    }
    /** Make root directories */
    for (int i = 0; i < root_directories_length; ++i) {
        path_join(path, 2, root, root_directories[i]);
        mkdir_recursively(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    }
    /** Copy binaries */
    for (int idx = 0; idx < copy_binaries_count; ++idx) {
        const char *directory = copy_binaries_directories[idx];
        const char **list = copy_binaries_list[idx];
        path_join(path, 2, root, directory);
        mkdir_recursively(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        for (int i = 0; i < copy_binaries_length[idx]; ++i) {
            path_join(path_bin, 2, directory, list[i]);
            if (access(path_bin, F_OK) == 0) {
                if (is_elf_file(path_bin))
                    copy_dependencies(root, path_bin);
                path_join(path, 3, root, directory, list[i]);
                if (access(path, F_OK) == 0) {
                    unlink(path);
                }
                if (copy_file(path_bin, path) != 0) {
                    fprintf(stderr, "Failed to copy file from %s to %s\n", path_bin, path);
                }
            }
        }
    }
    /** Make dev */
    path_join(path, 2, root, "dev/null");
    mknod(path, S_IFCHR | 0666, makedev(1, 3));
    path_join(path, 2, root, "dev/zero");
    mknod(path, S_IFCHR | 0666, makedev(1, 5));
    path_join(path, 2, root, "dev/random");
    mknod(path, S_IFCHR | 0666, makedev(1, 8));
    path_join(path, 2, root, "dev/urandom");
    mknod(path, S_IFCHR | 0666, makedev(1, 9));
    return 0;
}