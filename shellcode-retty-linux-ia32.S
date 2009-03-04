#if defined(__linux__) && defined(__i386)
/** injcode/shellcode-retty-linux-ia32.S
 *   
 *  Copyright(c) Thomas Habets 2009
 */
        
#include "asm-constants.h"
        /* data map */
        .equ    teststr,        0   /* 10 */
        .equ    socketstruct,   12  /* 12 */
        .equ    connectstruct,  24  /* 12 + 110 */
        .equ    recvstruct,     144 /* 12 */
        .equ    msghdr,         160 /* 28 */
        .equ    iovec,          188 /* 8 */
        .equ    cmsg,           196 /* 24 */
        .equ    scratchdata,    220 /* 4 */
        .equ    childfunc,      224 /* 4 */
        .equ    childpid,       228 /* 4 */
        .equ    oldtio,         232 /* 60 */

        /* variables (can be inside structs) */
        .equ    socketfd,       24  /* permanent location of fd */
        .equ    fd0,            208 /* 4 */
        .equ    fd1,            212 /* 4 */
        .equ    fd2,            216 /* 4 */
        
        .text
        
.globl shellcodeRetty
shellcodeRetty:

        # Debug print
        #movl   $SYS_write, %eax
        #movl   $2, %ebx    # stderr
        #leal   teststr(%ebp), %ecx
        #movl   $10, %edx   # len
        #int    $0x80
        #movl    $10, %ebx       # step 10 - debug print
        #cmpl    $0, %eax
        #jl      errout

        # ioctl(0, TCGETS, &oldtio)
        movl    $SYS_ioctl, %eax
        movl    $0, %ebx
        movl    $TCGETS, %ecx
        leal    oldtio(%ebp), %edx
        int     $0x80
        movl    $12, %ebx       # step 12
        cmpl    $0, %eax
        jl      errout
        
        # fork()
        movl    $SYS_fork, %eax
        int     $0x80
        cmpl    $0, %eax
        jne     parent
        jl      errout
        movl    childfunc(%ebp), %eax
        jmp     *%eax
parent:
        movl    %eax, childpid(%ebp)

        # setpgid()
setpgid:        
        movl    %eax, %ecx
        movl    $SYS_setpgid, %eax
        movl    $0, %ebx
        int     $0x80
        movl    $15, %ebx       # step 15
        cmpl    $0, %eax
        jl      setpgid

        # setsid()
        movl    $SYS_setsid, %eax
        int     $0x80
        movl    $73, %ebx       # step 73
        cmpl    $0, %eax
        jl      erroutclose

        # kill()
        movl    $SYS_kill, %eax
        movl    childpid(%ebp), %ebx
        movl    $SIGKILL, %ecx
        int     $0x80
                
        # waitpid()
        movl    $SYS_waitpid, %eax
        movl    childpid(%ebp), %ebx
        movl    $0, %ecx
        movl    $0, %edx
        int     $0x80
                
        # FIXME:        do three open(/dev/null)s, just in case
        
        # socket()
        movl    $SYS_socketcall, %eax
        movl    $SC_socket, %ebx
        leal    socketstruct(%ebp), %ecx      # socket struct
        int     $0x80
        movl    %eax, socketfd(%ebp)
        movl    $20, %ebx       # step 20 - socket
        cmpl    $0, %eax
        jl      errout
        # FIXME:        error handling

        # connect()
        movl    $SYS_socketcall, %eax
        movl    $SC_connect, %ebx
        leal    connectstruct(%ebp), %ecx
        int     $0x80
        movl    $30, %ebx       # step 30 - connect
        cmpl    $0, %eax
        jl      erroutclose

        # recvmsg()
        movl    socketfd(%ebp), %eax
        movl    %eax, recvstruct(%ebp)
        movl    $SYS_socketcall, %eax
        movl    $SC_recvmsg, %ebx
        leal    recvstruct(%ebp), %ecx
        int     $0x80
        movl    $40, %ebx       # step 40 - recvmsg
        cmpl    $1, %eax
        jne      errout

        # ioctl(fd, TIOCNOTTY, .) -- not needed. setsid() does it for us
        #movl    $SYS_ioctl, %eax
        #movl    $0, %ebx         # fd
        #movl    $TIOCNOTTY, %ecx
        #movl    $0, %edx
        #int     $0x80
        #movl    $45, %ebx       # step 45
        #cmpl    $0, %eax
        #jl      erroutclose

        # dup2(n, 0)
        movl    $SYS_dup2, %eax
        movl    fd0(%ebp), %ebx
        movl    $0, %ecx
        int     $0x80
        movl    $50, %ebx       # step 50 - dup2(n, 0)
        cmpl    $0, %eax
        jl      erroutclose

        # dup2(n, 1)
        movl    $SYS_dup2, %eax
        movl    fd1(%ebp), %ebx
        movl    $1, %ecx
        int     $0x80
        movl    $60, %ebx       # step 60 - dup2(n, 1)
        cmpl    $0, %eax
        jl      erroutclose

        # dup2(n, 2)
        movl    $SYS_dup2, %eax
        movl    fd2(%ebp), %ebx
        movl    $2, %ecx
        int     $0x80
        movl    $70, %ebx       # step 70 - dup2(n, 2)
        cmpl    $0, %eax
        jl      erroutclose

        # ioctl(fd, TIOCTTY, 1)
        movl    $SYS_ioctl, %eax
        movl    $0, %ebx         # fd
        movl    $TIOCSCTTY, %ecx
        movl    $1, %edx
        int     $0x80
        movl    $75, %ebx       # step 75
        cmpl    $0, %eax
        jne      erroutclose

        # ioctl(0, TCSETS, &oldtio)
        movl    $SYS_ioctl, %eax
        movl    $0, %ebx
        movl    $TCSETS, %ecx
        leal    oldtio(%ebp), %edx
        int     $0x80
        movl    $77, %ebx       # step 77
        cmpl    $0, %eax
        jl      errout

        # kill()
        movl    $SYS_kill, %eax
        movl    $0, %ebx
        movl    $SIGWINCH, %ecx
        int     $0x80

        # close(socket)
        movl    $SYS_close, %eax
        movl    socketfd(%ebp), %ebx
        int     $0x80
        movl    $80, %ebx       # step 80
        cmpl    $0, %eax
        jl      erroutclose

        # close(fd0)
        movl    $SYS_close, %eax
        movl    fd0(%ebp), %ebx
        int     $0x80
        movl    $90, %ebx       # step 90
        cmpl    $0, %eax
        jl      erroutclose

        # close(fd1)
        movl    $SYS_close, %eax
        movl    fd1(%ebp), %ebx
        int     $0x80
        movl    $100, %ebx       # step 100
        cmpl    $0, %eax
        jl      erroutclose

        # close(fd2)
        movl    $SYS_close, %eax
        movl    fd2(%ebp), %ebx
        int     $0x80
        movl    $110, %ebx       # step 110
        cmpl    $0, %eax
        jl      erroutclose
        
        movl    $255, %ebx
        # all done
        jmp     okout

.globl  shellcodeRettyChild
shellcodeRettyChild:
        # setpgid()
        movl    $SYS_setpgid, %eax
        movl    $0, %ebx
        movl    $0, %ecx
        int     $0x80

        # FIXME sleep(10)
        jmp     shellcodeRettyChild
        # exit(0)
        
erroutclose:
        #FIXME:  close socket
errout: 
okout:  
.globl shellcodeRettyEnd
shellcodeRettyEnd:   nop

#endif
