HEADERS = ../kernel/tpmttl.h

default: tpmttl

tpmttl.o: tpmttl_client.c $(HEADERS)
	riscv64-unknown-linux-gnu-gcc -c tpmttl_client.c -o tpmttl.o -w

tpmttl: tpmttl.o
	riscv64-unknown-linux-gnu-gcc tpmttl.o -o tpmttl

clean:
	-rm -f tpmttl.o
	-rm -f tpmttl