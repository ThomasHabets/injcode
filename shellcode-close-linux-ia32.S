#if defined(__linux__) && defined(__i386)
/** injcode/shellcode-close-linux-ia32.S
 *   
 *  Copyright(c) Thomas Habets 2009
 */
#include "asm-constants.h"

.globl shellcodeClose
shellcodeClose:
        movl   $SYS_close, %eax
        movl   (%ebp), %ebx
        int    $0x80
        xorl    %eax, %eax
.globl shellcodeCloseEnd
shellcodeCloseEnd:   nop
#endif
