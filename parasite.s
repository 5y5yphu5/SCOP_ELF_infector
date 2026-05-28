# parasite.s – ASLR‑aware __libc_start_main hijack (robust version)
.section .text
.globl parasite_entry
.type parasite_entry, @function

parasite_entry:
    # Save main's arguments
    push   %rdi               # argc
    push   %rsi               # argv
    push   %rdx               # envp

    # Save all callee‑saved registers
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

    # Restore callee‑saved registers
    pop    %r15
    pop    %r14
    pop    %r13
    pop    %r12
    pop    %rbp
    pop    %rbx

    # Resolve runtime address of main
    call   get_rip
get_rip:
    pop    %r11
    add    delta(%rip), %r11   # ADD, not SUB

    # Restore main's arguments and jump
    pop    %rdx
    pop    %rsi
    pop    %rdi
    jmp    *%r11

msg:
    .ascii "absurd\n"

delta:
    .quad 0x0
