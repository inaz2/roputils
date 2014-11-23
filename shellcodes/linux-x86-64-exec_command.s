        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rsi
        xor rcx, rcx
        mov cl, [rsi]
        inc rsi
        mov rbx, rsi
        cld
        rep lodsb
        mov [rsi], cl
main:
        push 59
        pop rax
        cqo
        push rdx
        pushw 0x632d
        mov rsi, rsp
        movabs rdi, 0x68732f2f6e69622f
        push rdx
        push rdi
        mov rdi, rsp
        push rdx
        push rbx
        push rsi
        push rdi
        mov rsi, rsp
        syscall
caller:
        call callee
arg:
        .byte 2
        .ascii "ls"
