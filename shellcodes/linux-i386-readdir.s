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
        int 0x80                     # open
        xchg ebx, eax
        xchg ecx, eax
        lea edx, [edi+1]
        lea eax, [edi+0x59]
loop:
        pushad
        int 0x80                     # readdir
        xchg esi, ecx
        test eax, eax
        je exit
        mov dx, [esi+8]
        lea ecx, [esi+10]
        mov byte ptr [ecx+edx], 0xa  # '\n'
        inc edx
        lea ebx, [edi+1]
        lea eax, [edi+4]
        int 0x80                     # write
        popad
        jmp loop
exit:
        xor ebx, ebx
        lea eax, [edi+1]
        int 0x80                     # exit
caller:
        call callee
arg:
        .byte 1
        .ascii "."
