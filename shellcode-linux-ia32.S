/* toscreen/shellcode-linux-ia32.S
#
# Copyright(c) Thomas Habets 2009
#
# http://foosec.pl/pub/info/syscalls_linux_2_2.html
# dup2=63, read=3, write=4, close=6, fork=2
*/
        .equ    SYS_waitpid,     7
        .equ    SYS_setpgid,     57
        .text
.globl shellcode
shellcode:
        movl    %eax, %ebp      # database

        movl   $4, %eax    # write()
        movl   $2, %ebx    # stderr
        movl   %ebp, %ecx  # addr of string
        movl   $10, %edx   # len
        int    $0x80
        movl    $10, %ebx       # step 10 - debug print
        cmpl    $0, %eax
        jl      errout

        # fork()
        movl    $2, %eax
        int     $0x80
        cmpl    $0, %eax
        jne     parent
        jl      errout
        movl    224(%ebp), %eax
        jmp     *%eax
parent:
        movl    %eax, 228(%ebp)

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
        movl    $66, %eax
        int     $0x80
        movl    $73, %ebx       # step 73
        cmpl    $0, %eax
        jl      erroutclose
        
        # waitpid()
        movl    %eax, %ebx
        movl    $SYS_waitpid, %eax
        movl    %ebp, %ecx
        movl    $0, %edx
        int     $0x80
                
        # FIXME:        do three open(/dev/null)s, just in case
        
        # socket()
        movl    $102, %eax      # socketcall
        movl    $1, %ebx        # socket()
        movl    %ebp, %ecx      # socket struct
        addl    $12, %ecx
        int     $0x80
        movl    %eax, 24(%ebp)
        movl    $20, %ebx       # step 20 - socket
        cmpl    $0, %eax
        jl      errout
        # FIXME:        error handling

        # connect()
        movl    $102, %eax      # socketcall()
        movl    $3, %ebx        # connect()
        movl    %ebp, %ecx      # socket struct
        addl    $24, %ecx
        int     $0x80
        movl    $30, %ebx       # step 30 - connect
        cmpl    $0, %eax
        jl      erroutclose

        # recvmsg()
        movl    24(%ebp), %eax  # copy socket fd
        movl    %eax, 144(%ebp)
        movl    $102, %eax      # socketcall()
        movl    $17, %ebx       # recvmsg()
        movl    %ebp, %ecx      # socket struct
        addl    $144, %ecx
        int     $0x80
        movl    $40, %ebx       # step 40 - recvmsg
        cmpl    $1, %eax
        jne      errout

        # ioctl(fd, TIOCNOTTY, .)
        movl    $54, %eax
        movl    $0, %ebx         # fd
        movl    $0x5422, %ecx    # TIOCNOTTY
        movl    $0, %edx
        int     $0x80
        movl    $45, %ebx       # step 45
        cmpl    $0, %eax
        jl      erroutclose

        # dup2(n, 0)
        movl    $63, %eax
        movl    208(%ebp), %ebx
        movl    $0, %ecx
        int     $0x80
        movl    $50, %ebx       # step 50 - dup2(n, 0)
        cmpl    $0, %eax
        jl      erroutclose

        # dup2(n, 1)
        movl    $63, %eax
        movl    212(%ebp), %ebx
        movl    $1, %ecx
        int     $0x80
        movl    $60, %ebx       # step 60 - dup2(n, 1)
        cmpl    $0, %eax
        jl      erroutclose

        # dup2(n, 2)
        movl    $63, %eax
        movl    216(%ebp), %ebx
        movl    $2, %ecx
        int     $0x80
        movl    $70, %ebx       # step 70 - dup2(n, 2)
        cmpl    $0, %eax
        jl      erroutclose

        # ioctl(fd, TIOCTTY, 1)
        movl    $54, %eax
        movl    $0, %ebx         # fd
        movl    $0x540E, %ecx    # TIOCSCTTY
        movl    $1, %edx
        int     $0x80
        movl    $75, %ebx       # step 75
        cmpl    $0, %eax
        jne      erroutclose

        # close(socket)
        movl    $6, %eax
        movl    24(%ebp), %ebx
        int     $0x80
        movl    $80, %ebx       # step 80
        cmpl    $0, %eax
        jl      erroutclose

        # close(fd0)
        movl    $6, %eax
        movl    208(%ebp), %ebx
        int     $0x80
        movl    $90, %ebx       # step 90
        cmpl    $0, %eax
        jl      erroutclose

        # close(fd1)
        movl    $6, %eax
        movl    212(%ebp), %ebx
        int     $0x80
        movl    $100, %ebx       # step 100
        cmpl    $0, %eax
        jl      erroutclose

        # close(fd2)
        movl    $6, %eax
        movl    216(%ebp), %ebx
        int     $0x80
        movl    $110, %ebx       # step 110
        cmpl    $0, %eax
        jl      erroutclose
        
        movl    $255, %ebx
        # all done
        jmp     okout

.globl  shellcodeChild
shellcodeChild:
        # setpgid()
        movl    $SYS_setpgid, %eax
        movl    $0, %ebx
        movl    $0, %ecx
        int     $0x80

        # FIXME sleep(10)
        jmp     shellcodeChild
        # exit(0)
        
erroutclose:
        #FIXME:  close socket
errout: 
okout:  
.globl shellcodeEnd
shellcodeEnd:   nop
