        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop ecx
loop:
        xorb [ecx], 0
        je data
        inc ecx
        jmp loop
caller:
        call callee
data:
        int3
