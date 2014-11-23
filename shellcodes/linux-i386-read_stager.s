        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop ecx
        push 3
        pop eax
        cdq
        mov ebx, edx
        inc edx
        shl edx, 12
        int 0x80
        jmp stage
caller:
        call callee
stage:
        int3
