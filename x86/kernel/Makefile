obj-m += tpmttl.o

KBUILD_CFLAGS += -w -msse4 -mpreferred-stack-boundary=4 -O2

all:
	make -C /lib/modules/6.8.0/build M=$(PWD) modules
clean:
	make -C /lib/modules/6.8.0/build M=$(PWD) clean
