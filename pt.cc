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
#include <errno.h>
#include <poll.h>
#include <pty.h>  /* for openpty and forkpty */
#include <utmp.h> /* for login_tty */
#include <string>

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
const unsigned int wordsize = 4;
const int pagesize = 4096;
typedef unsigned long word_t;
extern "C" char* shellcode();
extern "C" char* shellcodeEnd();
extern "C" char* shellcodeChild();

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
send_fds(int sd, int proxyfd)
{
        int fds[3] = { proxyfd,
                       proxyfd,
                       proxyfd };
        char buf[CMSG_SPACE(sizeof fds)];

        struct msghdr msg;
        memset(&msg,0,sizeof(msg));
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
        
        if (0 > sendmsg(sd, &msg, 0)) {
                fprintf(stderr, "P> sendmsg(%d, %p) %s\n",
                        sd, &msg, strerror(errno));
        }
        return 0;
}

void
dumpWaitStatus(int status)
{
        if (WIFEXITED(status)) {
                printf("exited: %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
                printf("signaled: %d\n", WTERMSIG(status));
        } else if (WIFSTOPPED(status)) {
                printf("stopped with signal %d\n", WSTOPSIG(status));
        } else if (WIFCONTINUED(status)) {
                printf("cont\n");
        }
}

void
child(int proxyfd)
{
        int server_socket = socket(PF_UNIX, SOCK_STREAM, 0);

        struct sockaddr_un server_address = { AF_UNIX,
                                              "\0init_console" };
        if (bind(server_socket, (struct sockaddr *) &server_address,
                 sizeof server_address)) {
                fprintf(stderr, "P> bind() error %s\n", strerror(errno));
        }
        if (listen(server_socket, 1)) {
                fprintf(stderr, "P> listen() error %s\n", strerror(errno));
        }
        
        struct sockaddr_un client_address;
        socklen_t client_address_length = sizeof client_address;
        fprintf(stderr, "P> waiting for inject code to connect...\n");
        int cli = accept(server_socket,
                         (struct sockaddr*)&client_address,
                         &client_address_length);
        if (0 > cli) {
                fprintf(stderr, "P> accept() error %s\n", strerror(errno));
        }
        close(server_socket);
        fprintf(stderr, "P> connected, sending...\n");
        send_fds(cli, proxyfd);
        fprintf(stderr, "P> all done\n");
        sleep(3);
        exit(0);
}

std::string
readFd(int fd)
{
        char buf[128];
        ssize_t n;

        n = read(fd, buf, sizeof(buf));
        if (!n) {
                return "";
        }
        if (0 > n) {
                perror("read");
                return "";
        }
        return std::string(buf, &buf[n]);
}

void
setRawTerminal(int fd)
{
        struct termios tio;
        if (tcgetattr(fd, &tio)) {
                fprintf(stderr, "---------- tcgetattr!\n");
        }
        cfmakeraw(&tio);
        if (tcsetattr(fd, TCSANOW, &tio)) {
                fprintf(stderr, "---------- tcsetattr!\n");
        }
}

int
main(int argc, char **argv)
{
        int proxyfdm, proxyfds;
        struct termios orig_tio;
        struct winsize ws;
        if (0 > tcgetattr(0, &orig_tio)) {
                perror("tcgetattr(0, ...)");
                return 1;
        }
        if (0 > ioctl(0, TIOCGWINSZ, &ws)) {
                perror("ioctl(0, TIOCGWINSZ, ...)");
                return 1;
        }


        if (0 > openpty(&proxyfdm, &proxyfds, NULL, &orig_tio, &ws)) {
                //if (0 > openpty(&proxyfdm, &proxyfds, NULL, NULL, NULL)) {
                perror("openpty()");
                return 1;
        }

        int childpid = fork();
        if (!childpid) {
                sleep(1);
                close(proxyfdm);
                child(proxyfds);
                return 0;
        }
        close(proxyfds);
        sleep(2);


        int err;
        pid = atoi(argv[1]);

        f = stdout;

        // background it
        kill(pid, SIGSTOP);
        kill(pid, SIGCONT);
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
        kill(pid, SIGCONT); // in case it was reading from terminal at the time
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
                size_t s = (word_t)shellcodeEnd-(word_t)shellcode;
                printf("Shellcode size is %d\n", s);
                memcpy(newcodepage, (char*)shellcode, s);
                       
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

        // recvmsg() call (starts at 144)
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

        // symbols
        if (1) {
                *(word_t*)&newdatapage[224] = codebase
                        + ((word_t)shellcodeChild-(word_t)shellcode);
        }

        // setup registers
        if ((err = ptrace(PTRACE_GETREGS, pid, NULL,
                          &newregs))) {
                perror("getregs");
        }
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
                if (0 || last != time(0)) {
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

                        if ((err = ptrace(PTRACE_GETREGS, pid, NULL,
                                          &newregs))) {
                                perror("getregs");
                        }
                        dumpregs(&newregs);
                        printf("%p .. %p .. %p\n",
                               (void*)codebase,
                               (void*)newregs.eip,
                               (void*)(codebase + pagesize)
                               );
                }

                if ((err = ptrace(PTRACE_GETREGS, pid, NULL, &newregs))) {
                        perror("getregs");
                }
        } while(newregs.eip != (long)(codebase  + pagesize));

        // print status
        fprintf(f,"Done\n");
        if ((err = ptrace(PTRACE_GETREGS, pid, NULL, &newregs))) {
		perror("getregs");
        }
        fprintf(f,"%%eax : %d %s\n", (int)newregs.eax,
                strerror(-newregs.eax));
        fprintf(f,"%%ebx : step %d\n", (int)newregs.ebx);
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
        if ((err = ptrace(PTRACE_DETACH, pid, NULL, NULL))) {
		perror("detach");
        }

        printf("Waiting for helper child\n");
        waitpid(childpid, NULL,0);
        
        printf("---attach now to %d----\n", getpid());
        //        sleep(10);
        printf("---client is taking over----\n");


        struct termios oldtio;
        tcgetattr(0, &oldtio);
        setRawTerminal(0);
        std::string to0, to1, to2;
        bool todie = false;
        while (!todie || !to1.empty() || !to2.empty()) {
                struct pollfd fds[3];
                int nfds;

                
                fds[0].fd = proxyfdm;
                fds[0].events = POLLIN;
                fds[0].revents = 0;
                fds[1].fd = 0;
                fds[1].events = POLLIN;
                fds[1].revents = 0;
                fds[2].fd = 1;
                fds[2].events = POLLIN;
                fds[2].revents = 0;

                if (!to0.empty()) {
                        fds[0].events |= POLLOUT;
                }
                if (!to1.empty()) {
                        fds[1].events |= POLLOUT;
                }
                if (!to2.empty()) {
                        fds[2].events |= POLLOUT;
                }

                nfds = poll(fds, 3, -1);

                if (fds[0].revents & POLLHUP) {
                        // process died/detached from terminal
                        //close(proxyfdm);
                        //proxyfdm = -1;
                        todie = true;
                        break;
                }

                if (fds[0].revents & POLLIN) {
                        //printf("Write from 0 to 2\n");
                        to2 += readFd(fds[0].fd);
                }
                if ((fds[1].revents & POLLIN)) {
                        //printf("Write from 1 to 0\n");
                        to0 += readFd(fds[1].fd);
                }
                if (!to0.empty() && (fds[0].revents & POLLOUT)) {
                        write(fds[0].fd, to0.data(), to0.size());
                        to0 = "";
                }
                if (!to1.empty() && (fds[1].revents & POLLOUT)) {
                        write(fds[1].fd, to1.data(), to1.size());
                        to1 = "";
                }
                if (!to2.empty() && (fds[2].revents & POLLOUT)) {
                        write(fds[2].fd, to2.data(), to2.size());
                        to2 = "";
                }
                
        }
        tcsetattr(0, TCSANOW, &oldtio);
}
