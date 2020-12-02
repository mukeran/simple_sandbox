C_SOURCES = $(wildcard src/*.c)
OBJ = ${C_SOURCES:.c=.o}
HEADERS = $(wildcard src/*.h)

CC = gcc ${EXTRA}
LD = ld

all: sandbox

run: all
	./sandbox

debug: clean
	EXTRA=-g make all

%.o: %.c ${HEADERS}
	${CC} -c $< -o $@

sandbox: ${OBJ}
	${LD} -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o $@ /usr/lib/x86_64-linux-gnu/crt1.o /usr/lib/x86_64-linux-gnu/crti.o $^ -lc /usr/lib/x86_64-linux-gnu/crtn.o

clean:
	rm -rf ${OBJ}
	rm -rf sandbox