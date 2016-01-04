        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rsi
loop:
        xor byte ptr [rsi], 0x00
        jz stage
        inc rsi
        jmp loop
        .skip 4
caller:
        call callee
stage:
        int3
