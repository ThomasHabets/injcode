#if defined(__linux__) && defined(__i386)
/** injcode/shellcode-dup2-linux-ia32.S
 *   
 *  Copyright(c) Thomas Habets 2009
 */
#include "asm-constants.h"

.globl shellcodeDup2
shellcodeDup2:
        # open()
        movl    $SYS_open, %eax
        leal    12(%ebp), %ebx
        movl    4(%ebp), %ecx
        movl    8(%ebp), %edx
        int     $0x80
        cmpl    $0, %eax
        jl      .Lerrout_open
        movl    %eax, %ebx

        # dup2()
        movl    $SYS_dup2, %eax
        movl    (%ebp), %ecx
        int     $0x80
        cmpl    $0, %eax
        jl      .Lerrout_dup2

        # close()
        movl    $SYS_close, %eax
        int     $0x80
        cmpl    $0, %eax
        jl      .Lerrout_close

        # all done
        xorl    %eax, %eax
        jmp     shellcodeDup2End

.Lerrout_close:
.Lerrout_dup2:
        movl    $SYS_close, %eax
        int     $0x80
.Lerrout_open:
        
.globl shellcodeDup2End
shellcodeDup2End:   nop
#endif
