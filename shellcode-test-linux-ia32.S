#include "asm-constants.h"

        .equ    teststr,        0
        
.globl shellcodeTest
shellcodeTest:
        # Debug print
        movl   $SYS_write, %eax
        movl   $2, %ebx    # stderr
        leal   teststr(%ebp), %ecx
        movl   $10, %edx   # len
        int    $0x80
        #movl    $10, %ebx       # step 10 - debug print
        #cmpl    $0, %eax
        #jl      errout
.globl shellcodeTestEnd
shellcodeTestEnd:   nop
