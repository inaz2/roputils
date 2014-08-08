        .intel_syntax noprefix
        .globl _start
_start:
        xor rdx, rdx
        lea rdi, [rdx+4]   /* fd */
        lea rsi, [rdx+2]
loop:
        lea rax, [rdx+33]  /* dup2 */
        syscall
        dec rsi
        jns loop
next:
        int3
