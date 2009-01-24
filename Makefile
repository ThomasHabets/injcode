all: injcode

injcode: injcode.o inject.o retty.o shellcode-test-linux-ia32.o shellcode-linux-ia32.o
	$(CXX) -o $@ $^ -lutil

pt:
	g++ -Wall -W -g -o pt pt.cc shellcode-linux-ia32.S -lutil
b.s:
	gcc -c -g -Wa,-a,-ad b.c > b.lst

clean:
	rm -f *.o pt pt2