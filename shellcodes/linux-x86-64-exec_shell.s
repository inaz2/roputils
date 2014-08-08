        .intel_syntax noprefix
        .globl _start
_start:
        xor rdx, rdx
        push rdx
        mov rax, 0x68732f2f6e69622f  /* "/bin//sh" */
        push rax
        mov rdi, rsp
        push rdx
        push rdi
        mov rsi, rsp
        lea rax, [rdx+59]            /* execve */
        syscall
