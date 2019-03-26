.intel_syntax noprefix

.global rsaenc

/*
rsi: src_ptr
rdi: des_ptr
rcx: size

mem[rdi:rdi+size] += mem[rsi:rsi+size]
*/
add:
    push rcx
    xor rax, rax
loop_add:
    mov rdx, [rsi+rax*8]
    adc [rdi+rax*8], rdx
    inc rax
    loop loop_add
    pop rcx
    ret

/*
rsi: src_ptr
rdi: des_ptr
rcx: size
rbp: n

mem[rdi:rdi+size] += mem[rsi:rsi+size]
mem[rdi:rdi+size] %= n
*/
modadd:
    call add
    mov rsi, rbp
greater_than_zero:
    push rcx
    xor rax, rax
sub:
    mov rdx, [rsi+rax*8]
    sbb [rdi+rax*8], rdx
    inc rax
    loop sub
    pop rcx
    jnb greater_than_zero
    call add
    ret

/*
rsi: b
r8: result
r9: a
r10: buf
rbp: n

result = a*b % n
*/
modmul:
    push 0x11 # 17 qwords
    pop rdx
    /* memset(result, 0, 0x10) */
    mov rdi, r8 # result
    xor rax, rax
    mov rcx, rdx
    rep stosq
    /* mem[buf:buf+0x11] = mem[rsi:rsi+0x10] */
    mov rdi, r10 # buf
    mov rcx, rdx
    rep movsq [rdi], [rsi]
    #
    mov rcx, rdx
    xor rbx, rbx # bit_offset
loop_modmul:
    mov rsi, r9 # a
    bt [rsi], rbx
    mov rsi, r10 # buf
    push rsi
    jnb bit_zero
    mov rdi, r8 # result
    call modadd
bit_zero:
    pop rsi
    mov rdi, rsi
    call modadd
    #
    inc rbx
    mov rax, rbx
    shr rax, 6
    cmp rax, rcx
    jnz loop_modmul
    ret

/*
rdi: result
rsi: m
rdx: n

result = m^3 % n
*/
rsaenc:
    /* prologue */
    push rbx
    push rbp
    sub rsp, 0x110 # buf1: [rsp+0x80], buf2: [rsp]
    mov r11, rdi # backup rdi
    /* buf1 = m*m % n */
    mov rbp, rdx
    mov r10, rsp
    mov DWORD PTR [rsi+124], 1
    mov r9, rsi
    lea r8, [rsp+0x88]
    call modmul
    /* result = buf1*m % n */
    mov rsi, r8
    mov r8, r11
    call modmul
    /* epilogue */
    add rsp, 0x110
    pop rbp
    pop rbx
    ret
