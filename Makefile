#CC = /work/dreambox/toolchains/mipsel-unknown-linux-gnu/bin/mipsel-unknown-linux-gnu-gcc
CC ?= gcc
all: boxkey

twofish:
	@${CC} -g  -O0 twofish.c jet_twofish.c des.c -o twofish

boxkey:
	@${CC} -g  -O0 boxkey.c jet_twofish.c des.c  -o boxkey
	@i686-w64-mingw32-gcc-win32 -g -O0 boxkey.c jet_twofish.c des.c -o boxkey.exe


.PHONY: all twofish boxkey
