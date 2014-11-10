        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop eax
        xor edx, edx
        lea esi, [eax+1]
        mov ecx, esi
        add cl, [eax]
        mov [ecx], dl
        xor edx, edx
        xor ecx, ecx
        mov cx, 0x632d     /* "-c" */
        push ecx
        mov ecx, esp
        push edx
        push 0x68732f2f
        push 0x6e69622f    /* "/bin//sh" */
        mov ebx, esp
        push edx
        push esi
        push ecx
        push ebx
        mov ecx, esp
        lea eax, [edx+11]  /* execve */
        int 0x80
caller:
        call callee
pstring:
        .byte 2
        .ascii "ls"
