        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rsi
        xor rcx, rcx
        mov cl, [rsi]
        inc rsi
        mov [rsi+rcx], ch
main:
        push 59
        pop rax
        cqo
        push rdx
        pushw 0x632d
        mov rbx, rsp
        movabs rdi, 0x68732f2f6e69622f
        push rdx
        push rdi
        mov rdi, rsp
        push rdx
        push rsi
        push rbx
        push rdi
        mov rsi, rsp
        syscall
caller:
        call callee
arg:
        .byte 2
        .ascii "ls"
