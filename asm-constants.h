/** injcode/asm-constants.h
 *   
 *  Copyright(c) Thomas Habets 2009
 */
#ifdef __linux__
        /*
        Syscall numbers http://foosec.pl/pub/info/syscalls_linux_2_2.html
        */
        .equ    SYS_fork,       2
        .equ    SYS_read,       3
        .equ    SYS_write,      4
        .equ    SYS_open,       5
        .equ    SYS_close,      6
        .equ    SYS_waitpid,    7
        .equ    SYS_kill,       37
        .equ    SYS_ioctl,      54
        .equ    SYS_setpgid,    57
        .equ    SYS_dup2,       63
        .equ    SYS_setsid,     66
        .equ    SYS_socketcall, 102

        .equ    SC_socket,      1
        .equ    SC_connect,     3
        .equ    SC_recvmsg,     17

        .equ    TIOCSCTTY,      0x540E
        .equ    TIOCNOTTY,      0x5422
        .equ    TCGETS,         0x5401
        .equ    TCSETS,         0x5402

        .equ    SIGKILL,        9
        .equ    SIGWINCH,       28
#endif
