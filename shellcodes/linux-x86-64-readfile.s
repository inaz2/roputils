        .intel_syntax noprefix
        .globl _start
_start:
        jmp caller
callee:
        pop rdi
        xor rcx, rcx
        mov cl, [rdi]
        inc rdi
        mov [rdi+rcx], ch
main:
        xor rsi, rsi
        push 2
        pop rax
        syscall                 # open
        xchg rdi, rax
        xchg rsi, rax
        push 1
        pop rdx
        shl rdx, 12
        syscall                 # read
        xchg rdx, rax
        push 1
        pop rdi
        push 1
        pop rax
        syscall                 # write
        xor rdi, rdi
        push 60
        pop rax
        syscall                 # exit
caller:
        call callee
arg:
        .byte 11
        .ascii "/etc/passwd"
