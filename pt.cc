#include <sys/ptrace.h>
#include <cstdio>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

struct user_regs_struct {
        long ebx, ecx, edx, esi, edi, ebp, eax;
        unsigned short ds, __ds, es, __es;
        unsigned short fs, __fs, gs, __gs;
        long orig_eax, eip;
        unsigned short cs, __cs;
        long eflags, esp;
        unsigned short ss, __ss;
};

int pid;
const int wordsize = 4;
const int pagesize = 4096;
typedef unsigned long word_t;
extern "C" char* shellcode();
extern "C" char* shellcodeEnd();

void
peekpoke(const char *data, unsigned long addr, size_t len, bool poke)
{
        unsigned long them;
        const char *us;
        int err;

        us = data;
        them = addr;

        for(;
            len >= wordsize;
            len -= wordsize, them += wordsize, us += wordsize) {
                if (poke) {
                        if ((err = ptrace(PTRACE_POKEDATA,
                                          pid,
                                          them,
                                          *(word_t*)us))) {
                                perror("poke");
                        }
                } else {
                        *(word_t*)us = ptrace(PTRACE_PEEKDATA,
                                               pid,
                                               them,
                                               NULL);
                        //printf("%p: %.8x\n", them, *(word_t*)us);
                }
        }
}

void
peek(const char *data, unsigned long addr, size_t len)
{
        peekpoke(data, addr, len, false);
}
void
poke(const char *data, unsigned long addr, size_t len)
{
        peekpoke(data, addr, len, true);
}

int
main(int argc, char **argv)
{
        int err;
        pid = atoi(argv[1]);

        word_t codebase;
        word_t database;

        char olddatapage[pagesize];
        char oldcodepage[pagesize];
        struct user_regs_struct oldregs;
        
#if 0
        char shellcode[] =
                "\xeb\x15\x5e\xb8\x04\x00"
                "\x00\x00\xbb\x02\x00\x00\x00\x89\xf1\xba"
                "\x0c\x00\x00\x00\xcd\x80\xcc\xe8\xe6\xff"
                "\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f"
                "\x72\x6c\x64\x0a\x00";
#endif
        char newdatapage[pagesize];
        char newcodepage[pagesize];
        struct user_regs_struct newregs;

        if ((err = ptrace(PTRACE_ATTACH, pid, NULL, NULL))) {
		perror("attach");
		exit(1);
	}
        waitpid(pid, NULL, 0);

        // save old
        if ((err = ptrace(PTRACE_GETREGS, pid, NULL, &oldregs))) {
		perror("getregs");
        }
        printf("%%eip : 0x%.8lx\n", oldregs.eip);
        printf("%%esp : 0x%.8lx\n", oldregs.esp);

        codebase = oldregs.eip & ~(pagesize-1);
        database = oldregs.esp & ~(pagesize-1);

        peek(olddatapage, database, pagesize);
        peek(oldcodepage, codebase, pagesize);

        // make new
        memset(newcodepage, 0x90, pagesize);
        if (1) {
                memcpy(newcodepage,
                       (char*)shellcode,
                       (word_t)shellcodeEnd-(word_t)shellcode);
        }
        //                   123456789A
        strcpy(newdatapage, "Inject OK\n");

        // for socket() call
        int socketcall_socket[] = {AF_UNIX, SOCK_STREAM, 0};
        memcpy(&newdatapage[10],
               &socketcall_socket,
               sizeof(socketcall_socket));
        // pos 22: 4 bytes for results

        // for connect() call (starts at 22)
        int socketcall_connect[] = { database + 34,
                                     sizeof(struct sockaddr_un) };
        struct sockaddr_un su = { AF_UNIX, "\0init_console" };
        memcpy(&newdatapage[26],
               &socketcall_connect,
               sizeof(socketcall_connect));
        memcpy(&newdatapage[34],
               &su,
               sizeof(su));

        newcodepage[pagesize-1] = 0xcc;
        poke(newdatapage, database, pagesize);
        poke(newcodepage, codebase, pagesize);
        newregs.eip = codebase;
        newregs.eax = database;
        newregs.esp = database + pagesize - wordsize;
        if ((err = ptrace(PTRACE_SETREGS, pid, NULL, &newregs))) {
		perror("getregs");
        }

        // run
        do {
                if ((err = ptrace(PTRACE_CONT, pid, NULL, NULL))) {
                        perror("continue");
                }
                
                waitpid(pid, NULL, 0);

                if ((err = ptrace(PTRACE_GETREGS, pid, NULL, &newregs))) {
                        perror("getregs");
                }
                if (0) {
                        printf("%p .. %p .. %p\n",
                               codebase,
                               newregs.eip,
                               oldregs.eip + pagesize
                               );
                }
        } while(newregs.eip != codebase  + pagesize);

        // print status
        printf("Done\n");
        if ((err = ptrace(PTRACE_GETREGS, pid, NULL, &newregs))) {
		perror("getregs");
        }
        printf("%%eax : %d %s\n", newregs.eax, strerror(-newregs.eax));
        printf("%%ebp : 0x%.8lx\n", newregs.ebp);
        printf("%%eip : 0x%.8lx\n", newregs.eip);
        printf("%%esp : 0x%.8lx\n", newregs.esp);
        
        // restore
        poke(olddatapage, oldregs.esp & ~(pagesize-1), pagesize);
        poke(oldcodepage, oldregs.eip & ~(pagesize-1), pagesize);
        if ((err = ptrace(PTRACE_SETREGS, pid, NULL, &oldregs))) {
		perror("getregs");
        }
        if ((err = ptrace(PTRACE_CONT, pid, NULL, NULL))) {
		perror("getregs");
        }

        ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
