# toscreen/shellcode-linux-ia32.S
#
# Copyright(c) Thomas Habets 2009
#
# dup2=63, read=3, write=4, close=6
#
        .text
.globl shellcode
shellcode:
        movl    %eax, %ebp      # data area

        movl   $4, %eax    # write()
        movl   $2, %ebx    # stderr
        movl   %ebp, %ecx  # addr of string
        movl   $10, %edx   # len
        int    $0x80
        movl    $10, %ebx       # step 10 - debug print
        cmpl    $0, %eax
        jl      errout

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
        #movl    22(%ebp), %eax  # copy socket fd
        #movl    %eax, 144(%ebp)
        #movl    $102, %eax      # socketcall()
        #movl    $17, %ebx       # recvmsg()
        #movl    %ebp, %ecx      # socket struct
        #addl    $144, %ecx
        #int     $0x80
        #movl    $40, %ebx       # step 40 - recvmsg
        #cmpl    $0, %eax
        #jmp     errout
        #jl      errout

        # all done
        jmp     okout

erroutclose:
        #FIXME:  close socket
errout: 
okout:  
.globl shellcodeEnd
shellcodeEnd:   nop
