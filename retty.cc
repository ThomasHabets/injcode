// injcode/retty.cc
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>
#include <pty.h>  /* for openpty and forkpty */
#include <utmp.h> /* for login_tty */
#include <poll.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>

#include "inject.h"
#include "ErrHandling.h"
#include "injcode.h"

extern "C" char* shellcodeRetty();
extern "C" char* shellcodeRettyEnd();
extern "C" char* shellcodeRettyChild();

extern options_t options;

static int proxyfdm, proxyfds;
static pid_t childpid;
static struct termios orig_tio;

void
Retty::sigwinch(int unused)
{
        struct winsize ws;
        if (0 > ioctl(0, TIOCGWINSZ, &ws)) {
                throw ErrHandling::ErrSys("Retty::sigwinch",
                                          "ioctl",
                                          "TIOCGWINSZ");
                fprintf(stderr, "%s: ioctl(0, TIOCGWINSZ, ...): %s\n",
                        options.argv0, strerror(errno));
        }
        if (0 > ioctl(proxyfdm, TIOCSWINSZ, &ws)) {
                throw ErrHandling::ErrSys("Retty::sigwinch",
                                          "ioctl",
                                          "TIOCSWINSZ");
                fprintf(stderr, "%s: ioctl(0, TIOCSWINSZ, ...): %s\n",
                        options.argv0, strerror(errno));
        }
}

int
Retty::send_fds(int sd, int proxyfd)
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
                fprintf(stderr, "RettyChild> sendmsg(%d, %p) %s\n",
                        sd, &msg, strerror(errno));
        }
        return 0;
}

void
Retty::child(int proxyfd)
{
        int server_socket = socket(PF_UNIX, SOCK_STREAM, 0);

        struct sockaddr_un server_address = { AF_UNIX,
                                              "\0init_console" };
        if (bind(server_socket, (struct sockaddr *) &server_address,
                 sizeof server_address)) {
                fprintf(stderr, "RettyChild> bind() error %s\n",
                        strerror(errno));
        }
        if (listen(server_socket, 1)) {
                fprintf(stderr, "RettyChild> listen() error %s\n",
                        strerror(errno));
        }
        
        struct sockaddr_un client_address;
        socklen_t client_address_length = sizeof client_address;
        if (options.verbose) {
                printf("RettyChild> waiting for inject code to connect...\n");
        }
        int cli = accept(server_socket,
                         (struct sockaddr*)&client_address,
                         &client_address_length);
        if (0 > cli) {
                fprintf(stderr, "RettyChild> accept() error %s\n",
                        strerror(errno));
        }
        close(server_socket);
        if (options.verbose) {
                printf("RettyChild> connected, sending...\n");
        }
        send_fds(cli, proxyfd);
        if (options.verbose) {
                printf("RettyChild> all done\n");
        }
        //sleep(3);
        exit(0);
}

std::string
Retty::readFd(int fd)
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
Retty::setRawTerminal(int fd)
{
        struct termios tio;
        if (tcgetattr(fd, &tio)) {
                fprintf(stderr, "%s: tcgetattr(): %s\n", options.argv0,
                        strerror(errno));
                return;
        }
        cfmakeraw(&tio);
        if (tcsetattr(fd, TCSANOW, &tio)) {
                fprintf(stderr, "%s: tcsetattr(): %s\n", options.argv0,
                        strerror(errno));
        }
}


void
Retty::setupPty()
{
        struct winsize ws;
        if (0 > tcgetattr(0, &orig_tio)) {
                throw ErrHandling::ErrSys("retty setupPty",
                                          "tcgetattr",
                                          "");
        }
        if (0 > ioctl(0, TIOCGWINSZ, &ws)) {
                throw ErrHandling::ErrSys("retty setupPty",
                                          "ioctl",
                                          "");
                perror("ioctl(0, TIOCGWINSZ, ...)");
        }

        if (0 > openpty(&proxyfdm, &proxyfds, NULL, &orig_tio, &ws)) {
                throw ErrHandling::ErrSys("retty setupPty",
                                          "openpty",
                                          "");
        }
        childpid = fork();
        if (!childpid) {
                close(proxyfdm);
                child(proxyfds);
                exit(0);
        }
        close(proxyfds);
        signal(SIGWINCH, sigwinch);

        // FIXME: communicate with child so we know when it's ready.
        //        don't just sleep() arbitrarily.
        sleep(1);
}

Retty::Retty(Inject &injector)
        :InjMod(injector)
{
        setupPty();

        // background it
        kill(options.targetpid, SIGSTOP);
        kill(options.targetpid, SIGCONT);

        char data[injector.pageSize()];
        char code[injector.pageSize()];

        memset(code, 0x90, injector.pageSize());
        memset(data, 0, injector.pageSize());
        code[injector.pageSize()-1] = 0xcc;

        // test string 10B @ 0
        strcpy(data, "Inject OK\n");
        // socket() struct 12B @ 12
        {
                if (options.verbose > 1) {
                        printf("Setting up socket struct (size 12) at 12\n");
                }

                int socketcall_socket[] = {AF_UNIX, SOCK_STREAM, 0};
                memcpy(&data[12],
                       &socketcall_socket,
                       sizeof(socketcall_socket));
        } 

        // connect() struct (12 + 110)B @ 24
        {
                if (options.verbose > 1) {
                        printf("Setting up connect struct (size 12) at 24\n");
                }
                int socketcall_connect[] = { 0, // to be filled in
                                             injector.dataBase() + 36,
                                             sizeof(struct sockaddr_un) };
                memcpy(&data[24],
                       &socketcall_connect,
                       sizeof(socketcall_connect));

                if (options.verbose > 1) {
                        printf("Setting up connect sockaddr (size %d) at 36\n",
                               sizeof(struct sockaddr_un));
                }
                // FIXME: name of socket
                struct sockaddr_un su = { AF_UNIX, "\0init_console" };
                memcpy(&data[36],
                       &su,
                       sizeof(su));
        }

        // recvmsg() struct @ 144
        {
                int socketcall_recvmsg[] = { 0, // to be filled in
                                             injector.dataBase() + 160, // msg
                                             0 };
                memcpy(&data[144],
                       &socketcall_recvmsg,
                       sizeof(socketcall_recvmsg));

                int data_msg[] = { 0,0, // name
                                   injector.dataBase() + 188, 1, // iov
                                   injector.dataBase() + 196, 24, // control
                                   0,   // flags
                };
                memcpy(&data[160],
                       &data_msg,
                       sizeof(data_msg));

                int data_iovec[] = { injector.dataBase() + 220, 1};
                memcpy(&data[188],
                       &data_iovec,
                       sizeof(data_iovec));
        }

        // symbols
        {
                *(Inject::ptr_t*)&data[224] = injector.codeBase()
                        + ((Inject::ptr_t)shellcodeRettyChild
                           -(Inject::ptr_t)shellcodeRetty);
        }

        size_t s = (Inject::ptr_t)shellcodeRettyEnd
                - (Inject::ptr_t)shellcodeRetty;
        if (options.verbose) {
                printf("Shellcode size is %d\n", s);
        }
        memcpy(code, (char*)shellcodeRetty, s);

        injector.inject(code, data);
}

void
Retty::run()
{
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
}
