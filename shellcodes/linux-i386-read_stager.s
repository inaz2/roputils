        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop ecx
        xor ebx, ebx
        lea edx, [ebx+1]
        shl edx, 12
        lea eax, [ebx+3]  /* read */
        int 0x80
        jmp stage
caller:
        call callee
stage:
        int3
