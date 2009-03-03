#include "asm-constants.h"

.globl shellcodeClose
shellcodeClose:
        movl   $SYS_close, %eax
        movl   (%ebp), %ebx
        int    $0x80
        xorl    %eax, %eax
.globl shellcodeCloseEnd
shellcodeCloseEnd:   nop
