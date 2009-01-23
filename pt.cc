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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<errno.h>


struct user_regs_struct {
        long ebx, ecx, edx, esi, edi, ebp, eax;
        unsigned short ds, __ds, es, __es;
        unsigned short fs, __fs, gs, __gs;
        long orig_eax, eip;
        unsigned short cs, __cs;
        long eflags, esp;
        unsigned short ss, __ss;
};
        FILE *f;

void
dumpregs(struct user_regs_struct *regs)
{
        fprintf(f,"----------------------------\n");
        fprintf(f,"%%eip : 0x%.8lx\n", regs->eip);
        fprintf(f,"%%eax : 0x%.8lx\n", regs->eax);
        fprintf(f,"%%ebx : 0x%.8lx\n", regs->ebx);
        fprintf(f,"%%ecx : 0x%.8lx\n", regs->ecx);
        fprintf(f,"%%edx : 0x%.8lx\n", regs->edx);
        fprintf(f,"%%esi : 0x%.8lx\n", regs->esi);
        fprintf(f,"%%edi : 0x%.8lx\n", regs->edi);
        fprintf(f,"%%ebp : 0x%.8lx\n", regs->ebp);
        fprintf(f,"%%orig_eax : 0x%.8lx\n", regs->orig_eax);
        fprintf(f,"%%esp : 0x%.8lx\n", regs->esp);
        fflush(f);
}

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
send_fds(int sd)
{
        int fds[3] = {0,1,2};
        char buf[CMSG_SPACE(sizeof fds)];

        struct msghdr msg;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
        msg.msg_controllen = cmsg->cmsg_len;

        memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

        char ping = 23;
        struct iovec ping_vec;
        ping_vec.iov_base = &ping;
        ping_vec.iov_len = sizeof(ping);

        msg.msg_iov = &ping_vec;
        msg.msg_iovlen = 1;

        sendmsg(sd, &msg, 0);
        return 0;
}

void
finalWait()
{
        int status;
        fprintf(f, "waiting for pid %d...\n", pid);
        fprintf(f, "done waiting for pid %d\n", waitpid(pid, &status, 0));
        if (WIFEXITED(status)) {
                fprintf(f, "exited: %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
                fprintf(f, "signaled: %d\n", WTERMSIG(status));
        } else if (WIFSTOPPED(status)) {
                fprintf(f, "stopped: %d\n", WSTOPSIG(status));
        } else if (WIFCONTINUED(status)) {
                fprintf(f, "cont\n");
        }
        fflush(f);
}

void
child()
{
        int server_socket = socket(PF_UNIX, SOCK_STREAM, 0);

        struct sockaddr_un server_address = { AF_UNIX,
                                              "\0init_console" };
        bind(server_socket, (struct sockaddr *) &server_address,
             sizeof server_address);
        listen(server_socket, 1);
        
        struct sockaddr_un client_address;
        socklen_t client_address_length = sizeof client_address;
        int client_connection = accept(server_socket,
                                       (struct sockaddr*)&client_address,
                                       &client_address_length);
        close(server_socket);
        fprintf(stderr, "P> connected, sending...\n");
        send_fds(client_connection);
        fprintf(stderr, "P> all done\n");
        exit(0);
}

int
main(int argc, char **argv)
{
        int childpid = fork();
        if (!childpid) {
                child();
                return 0;
        }
        sleep(1);
        int err;
        pid = atoi(argv[1]);

        if (!(f = fopen("lala.log", "a+"))) {
                perror("fopen()");
        }
        fprintf(f, "setsid(): %d\n", setsid());
        fprintf(f, "TIOCNOTTY: %d %s\n", ioctl(0, TIOCNOTTY, NULL),
               strerror(errno));
        fflush(f);


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
        fprintf(f, "%%eip : 0x%.8lx\n", oldregs.eip);
        fprintf(f, "%%esp : 0x%.8lx\n", oldregs.esp);        
        fflush(f);

        codebase = oldregs.eip & ~(pagesize-1);
        database = oldregs.esp & ~(pagesize-1);

        peek(olddatapage, database, pagesize);
        peek(oldcodepage, codebase, pagesize);

        // make new code
        memset(newcodepage, 0x90, pagesize);
        if (1) {
                memcpy(newcodepage,
                       (char*)shellcode,
                       (word_t)shellcodeEnd-(word_t)shellcode);
        }
        //                   123456789A
        strcpy(newdatapage, "Inject OK\n");

        // for socket() call
        if (1) {
                printf("Setting up socket struct (size 12) at 12\n");
                int socketcall_socket[] = {AF_UNIX, SOCK_STREAM, 0};
                memcpy(&newdatapage[12],
                       &socketcall_socket,
                       sizeof(socketcall_socket));
                // pos 24: 4 bytes for results
        } 

        // for connect() call (starts at 24)
        if (1) {
                printf("Setting up connect struct (size 12) at 24\n");
                int socketcall_connect[] = { 0, // to be filled in
                                             database + 36,
                                             sizeof(struct sockaddr_un) };
                memcpy(&newdatapage[24],
                       &socketcall_connect,
                       sizeof(socketcall_connect));

                printf("Setting up connect struct sockaddr (size %d) at 36\n",
                       sizeof(struct sockaddr_un));
                struct sockaddr_un su = { AF_UNIX, "\0init_console" };
                memcpy(&newdatapage[36],
                       &su,
                       sizeof(su));
        }

        // recvmsg() call (starts at 148)
        if (1) {
                int socketcall_recvmsg[] = { 0, // to be filled in
                                             database + 160, // msg
                                             0 };
                memcpy(&newdatapage[144],
                       &socketcall_recvmsg,
                       sizeof(socketcall_recvmsg));

                int data_msg[] = { 0,0, // name
                                   database + 188, 1, // iov
                                   database + 196, 24, // control
                                   0,   // flags
                };
                memcpy(&newdatapage[160],
                       &data_msg,
                       sizeof(data_msg));

                int data_iovec[] = { database + 220, 1};
                memcpy(&newdatapage[188],
                       &data_iovec,
                       sizeof(data_iovec));
        }
        fflush(f);

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
        time_t last = 0;
        do {
                if ((err = ptrace(PTRACE_CONT, pid, NULL, NULL))) {
                        perror("PTRACE_CONT");
                }
                int status;
                waitpid(pid, &status, 0);
                if (last != time(0)) {
                        last = time(0);
                        fprintf(f, "waitpid status: %d %d %d %d\n",
                                WIFEXITED(status),
                                WIFSIGNALED(status),
                                WIFSTOPPED(status),
                                WIFCONTINUED(status));
                        if (WIFSTOPPED(status)) {
                                fprintf(f, "Stopping signal: %d\n",
                                        WSTOPSIG(status));
                        }
                        fflush(f);
                }

                if ((err = ptrace(PTRACE_GETREGS, pid, NULL, &newregs))) {
                        perror("getregs");
                }
                if (0) {
                        dumpregs(&newregs);
                        printf("%p .. %p .. %p\n",
                               codebase,
                               newregs.eip,
                               codebase + pagesize
                               );
                }
        } while(newregs.eip != codebase  + pagesize);

        // print status
        fprintf(f,"Done\n");
        if ((err = ptrace(PTRACE_GETREGS, pid, NULL, &newregs))) {
		perror("getregs");
        }
        fprintf(f,"%%eax : %d %s\n", newregs.eax, strerror(-newregs.eax));
        fprintf(f,"%%ebx : step %d\n", newregs.ebx);
        fprintf(f,"%%ebp : 0x%.8lx\n", newregs.ebp);
        fprintf(f,"%%eip : 0x%.8lx\n", newregs.eip);
        fprintf(f,"%%esp : 0x%.8lx\n", newregs.esp);
        dumpregs(&newregs);
        
        // restore
        poke(olddatapage, oldregs.esp & ~(pagesize-1), pagesize);
        poke(oldcodepage, oldregs.eip & ~(pagesize-1), pagesize);
        if ((err = ptrace(PTRACE_SETREGS, pid, NULL, &oldregs))) {
		perror("getregs");
        }
        if ((err = ptrace(PTRACE_CONT, pid, NULL, NULL))) {
		perror("getregs");
        }

        fprintf(f, "-------\n");fflush(f);

        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        waitpid(childpid, NULL,0);
        printf("About to close everything...\n");
        fprintf(f, "about to close all\n"); fflush(f);

        close(0);
        close(1);
        close(2);
        fprintf(f, "closed all\n");fflush(f);
        finalWait();
        fprintf(f, "wait done\n");fflush(f);
}
