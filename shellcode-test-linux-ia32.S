#if defined(__linux__) && defined(__i386)
/** injcode/shellcode-test-linux-ia32.S
 *   
 *  Copyright(c) Thomas Habets 2009
 */
#include "asm-constants.h"

        .equ    teststr,        0
        
.globl shellcodeTest
shellcodeTest:
        movl   $SYS_write, %eax
        movl   $2, %ebx    # stderr
        leal   teststr(%ebp), %ecx
        movl   $10, %edx   # len
        int    $0x80
        xorl    %eax, %eax
.globl shellcodeTestEnd
shellcodeTestEnd:   nop
#endif
