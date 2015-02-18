        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop esi
loop:
        xor byte ptr [esi], 0x00
        jz stage
        inc esi
        jmp loop
        .ascii "\x00\x00\x00\x00\x00\x00"
caller:
        call callee
stage:
        int3
