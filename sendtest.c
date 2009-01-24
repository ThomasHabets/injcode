#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

int
send_fds(int sd)
{
        int fds[3] = {0,1,2};
        char buf[CMSG_SPACE(sizeof fds)];

        struct msghdr msg = {
                .msg_control = buf,
                .msg_controllen = sizeof(buf),
        };

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
        msg.msg_controllen = cmsg->cmsg_len;

        memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

        char ping = 23;
        struct iovec ping_vec = {
                .iov_base = &ping,
                .iov_len = sizeof(ping),
        };
        
        msg.msg_iov = &ping_vec;
        msg.msg_iovlen = 1;
        
        sendmsg(sd, &msg, 0);
        return 0;
}

int recv_fds(int sd)
{
        int file_descriptors[3];
        char buffer[CMSG_SPACE(sizeof file_descriptors)];
        
        char ping;
        struct iovec ping_vec = {
                .iov_base = &ping,
                .iov_len = sizeof ping,
        };
        
        struct msghdr message = {
                .msg_control = buffer,
                .msg_controllen = sizeof buffer,
                .msg_iov = &ping_vec,
                .msg_iovlen = 1,
        };
        fprintf(stderr, "C> About to recvmsg\n");
        recvmsg(sd, &message, 0);
        fprintf(stderr, "C> done recvmsg\n");

        struct cmsghdr *cmessage = CMSG_FIRSTHDR(&message);
        memcpy(file_descriptors, CMSG_DATA(cmessage), sizeof file_descriptors);
        dup2(file_descriptors[0], STDIN_FILENO);
        close(file_descriptors[0]);
        dup2(file_descriptors[1], STDOUT_FILENO);
        close(file_descriptors[1]);
        dup2(file_descriptors[2], STDERR_FILENO);
        close(file_descriptors[2]);
}


int
parent(int pid, int fd)
{
        int p;
        p = send_fds(fd);
        fprintf(stderr, "P> %d\n", p);
}

int child(int fd)
{
        fprintf(stderr, "c> %d\n", recv_fds(fd));
}

int
main()
{
        int pid = fork();
        int fds[2];

        //pipe(fds);
        if (pid) {
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
                fprintf(stderr, "P> connected\n");
                parent(pid, client_connection);
                //parent(pid, fds[1]);
                close(client_connection);
        } else {
                sleep(1);
                struct sockaddr_un server_address = { AF_UNIX, "\0init_console" };
                int client_socket = socket(PF_UNIX, SOCK_STREAM, 0);
                connect(client_socket, (struct sockaddr *) &server_address, sizeof server_address);
                close(0);
                close(1);
                fopen("/dev/null", "r");
                fopen("/dev/null", "r");
                //close(fds[1]);
                child(client_socket);
                //child(fds[0]);
                printf("Hello world\n");
        }
}
