all:
	g++ -Wall -W -g -o pt pt.cc shellcode-linux-ia32.S -lutil
b.s:
	gcc -c -g -Wa,-a,-ad b.c > b.lst
