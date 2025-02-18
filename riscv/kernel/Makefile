obj-m += tpmttl.o

KBUILD_CFLAGS += -w -mpreferred-stack-boundary=4 -O2

all:
	make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -C /lib/modules/6.8.0/build M=$(PWD) modules

clean:
	make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -C /lib/modules/6.8.0/build M=$(PWD) clean