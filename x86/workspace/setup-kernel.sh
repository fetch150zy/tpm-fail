#!/bin/sh

insmod ../kernel/tpmttl.ko
../client/tpmttl 2
../client/tpmttl 3 >> /dev/null
