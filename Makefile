# injcode/Makefile
#
CXXFLAGS=-g
GIT=git
ECHO=echo
SED=sed
GZIP=gzip
TAR=tar
GPG=gpg

all: injcode

injcode: injcode.o \
inject.o \
retty.o \
testmodule.o \
closemodule.o \
shellcode-test-linux-ia32.o \
shellcode-close-linux-ia32.o \
shellcode-retty-linux-ia32.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lutil

injcode-%.tar.gz:
	$(GIT) archive --format=tar \
		--prefix=$(shell $(ECHO) $@ | $(SED) 's/\.tar\.gz//')/ \
		injcode-$(shell $(ECHO) $@|$(SED) 's/.*-//'|$(SED) 's/\.tar\.gz//') \
		| $(TAR) --delete injcode-$(shell $(ECHO) $@|$(SED) 's/.*-//'|$(SED) 's/\.tar\.gz//')/.be  | $(GZIP) -9 > $@
	$(GPG) -b -a $@

pt:
	g++ -Wall -W -g -o pt pt.cc shellcode-linux-ia32.S -lutil
b.s:
	gcc -c -g -Wa,-a,-ad b.c > b.lst

clean:
	rm -f *.o injcode
