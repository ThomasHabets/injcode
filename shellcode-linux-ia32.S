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
        movl   $1, %ebx    # stderr
        movl   %ebp, %ecx  # addr of string
        movl   $10, %edx   # len
        int    $0x80

        # socket()
        movl    $102, %eax      # socketcall
        movl    $1, %ebx        # socket()
        movl    %ebp, %ecx      # socket struct
        addl    $10, %ecx
        int     $0x80
        movl    %eax, 22(%ebp)
        # FIXME:        error handling

        # connect()
        movl    $102, %eax      # socketcall()
        movl    $3, %ebx        # connect()
        movl    %ebp, %ecx      # socket struct
        addl    $22, %ecx
        int     $0x80

.globl shellcodeEnd
shellcodeEnd:   nop
