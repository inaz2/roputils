        .intel_syntax noprefix
        .globl _start
_start:
        push 4
        pop rdi
        push 2
        pop rsi
loop:
        push 33
        pop rax
        syscall
        dec rsi
        jge loop
        int3
