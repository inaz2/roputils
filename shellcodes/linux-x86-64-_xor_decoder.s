        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rcx
loop:
        xorb [rcx], 0
        je data
        inc rcx
        jmp loop
caller:
        call callee
data:
        int3
