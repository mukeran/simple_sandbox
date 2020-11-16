#include <unistd.h>
int main() {
    char *argv[] = { NULL };
    char *envp[] = { NULL };
    execve("/bin/sh", argv, envp);
}