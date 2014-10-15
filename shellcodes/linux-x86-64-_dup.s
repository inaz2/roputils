        .intel_syntax noprefix
        .globl _start
_start:
        xor rdx, rdx
        push 4             /* fd */
        pop rdi
        push 2
        pop rsi
loop:
        push 33            /* dup2 */
        pop rax
        syscall
        dec rsi
        jns loop
next:
        int3
