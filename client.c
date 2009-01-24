#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<errno.h>
#include <signal.h>
void
doit()
{
        __asm__("movl    $54, %eax\n"
                "movl    $0, %ebx\n"
                "movl    $0x5422, %ecx\n"
                "movl    $0, %edx\n"
                "int     $0x80\n");
}

void sigint(int a)
{
        
}


int
main()
{
        int n = 0, t;
        int pid;
        if (0) {
                doit();
        }
        if (0) {
                //signal(SIGHUP, sigint);
                if (!(pid = fork())) {
                        //printf("killstop %d\n", kill(getppid(),SIGSTOP));
                        //printf("killcont %d\n", kill(getppid(),SIGCONT));
                        //printf("C setsid: %d\n", setsid());
                        printf("setpgrp(%d): %d\n", pid, setpgid(0, 0));
                        for(;;) {sleep(10); }
                }
                //printf("parent pid %d\n", getpid());
                //sleep(10);
                //printf("P setsid: %d\n", setsid());
        }
        if (0) {
                sleep(10);
                printf("setpgrp(%d): %d\n", pid, setpgid(getpid(), pid));
        }
        if (0) {
                printf("setsid: %d\n", setsid());
        }
        if (0) {
                t = ioctl(0, TIOCNOTTY, NULL);
                printf("ioctl(): %d %s\n", t, strerror(errno));
        }
        if (0) {
                t = setsid();
                printf("setsid: %d %s\n", t, 
                       strerror(errno));
        }
        for(;;) {
                printf("Loop pid=%d %d\n", getpid(), n++);
                //fprintf(stderr, "> lala\n");
                if (1) {
                        sleep(1);
                } else {
                        getchar();
                }
        }
}
