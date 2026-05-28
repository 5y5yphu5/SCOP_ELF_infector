.section .text
.globl parasite_entry
.type parasite_entry, @function

parasite_entry:
    push   %rdi               
    push   %rsi               
    push   %rdx               

    push   %rbx
    push   %rbp
    push   %r12
    push   %r13
    push   %r14
    push   %r15

    # Payload: write(1, "absurd\n", 7)
    mov    $1, %rax
    mov    $1, %rdi
    lea    msg(%rip), %rsi
    mov    $7, %rdx
    syscall

    pop    %r15
    pop    %r14
    pop    %r13
    pop    %r12
    pop    %rbp
    pop    %rbx

    call   get_rip
get_rip:
    pop    %r11
    add    delta(%rip), %r11

    pop    %rdx
    pop    %rsi
    pop    %rdi
    jmp    *%r11

msg:
    .ascii "absurd\n"

delta:
    .quad 0x0
