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
        syscall                     # open
        xchg rdi, rax
        xchg rsi, rax
        xor rdx, rdx
        not dx
        push 78
        pop rax
        syscall                     # getdents
loop:
        mov rax, [rsi]
        test rax, rax
        je exit
        mov dx, [rsi+16]
        lea r8, [rsi+rdx]
        sub rdx, 20
        lea rsi, [rsi+18]
        mov byte ptr [rsi+rdx], 0xa  # '\n'
        inc rdx
        push 1
        pop rdi
        push 1
        pop rax
        syscall                     # write
        mov rsi, r8
        jmp loop
exit:
        xor rdi, rdi
        push 60
        pop rax
        syscall                     # exit
caller:
        call callee
arg:
        .byte 1
        .ascii "."
