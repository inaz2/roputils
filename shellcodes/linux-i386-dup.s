        .intel_syntax noprefix
        .globl _start
_start:
        xor edx, edx
        lea ebx, [edx+4]
        lea ecx, [edx+2]
loop:
        lea eax, [edx+63]
        int 0x80
        dec ecx
        jge loop
        int3
