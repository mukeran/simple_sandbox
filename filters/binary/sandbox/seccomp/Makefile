all:
	gcc -shared -o seccomp_sandbox.so seccomp_sandbox.c -ldl -lseccomp -fPIC
	gcc -shared -m32 -o seccomp_sandbox.i386.so seccomp_sandbox.c -ldl -lseccomp -DARCH_32 -fPIC
clean:
	rm -rf *.so