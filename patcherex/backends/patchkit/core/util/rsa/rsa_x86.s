.intel_syntax noprefix

.global rsaenc

/*
esi: src_ptr
edi: des_ptr
ecx: size

mem[edi:edi+size] += mem[esi:esi+size]
*/
add:
    push ecx
    xor eax, eax
loop_add:
    mov edx, [esi+eax*4]
    adc [edi+eax*4], edx
    inc eax
    loop loop_add
    pop ecx
    ret

/*
esi: src_ptr
edi: des_ptr
ecx: size
ebp: n

mem[edi:edi+size] += mem[esi:esi+size]
mem[edi:edi+size] %= n
*/
modadd:
    call add
    mov esi, ebp
greater_than_zero:
    push ecx
    xor eax, eax
sub:
    mov edx, [esi+eax*4]
    sbb [edi+eax*4], edx
    inc eax
    loop sub
    pop ecx
    jnb greater_than_zero
    call add
    ret

/*
esi: b
[esp+0x4]: result
[esp+0x8]: a
[esp+0xc]: buf
ebp: n

result = a*b % n
*/
modmul:
    push 0x21 # 33 words
    pop edx
    /* memset(result, 0, 0x21) */
    mov edi, [esp+0x4] # result
    xor eax, eax
    mov ecx, edx
    rep stosd
    /* mem[buf:buf+0x21] = mem[esi:esi+0x21] */
    mov edi, [esp+0xc] # buf
    mov ecx, edx
    rep movsd
    #
    mov ecx, edx
    xor ebx, ebx # bit_offset
loop_modmul:
    mov esi, [esp+0x8] # a
    bt [esi], ebx
    mov esi, [esp+0xc] # buf
    push esi
    jnb bit_zero
    mov edi, [esp+0x4+0x4] # result
    call modadd
bit_zero:
    pop esi
    mov edi, esi
    call modadd
    #
    inc ebx
    mov eax, ebx
    shr eax, 5
    cmp eax, ecx
    jnz loop_modmul
    ret

/*
[esp+0x4]: result
[esp+0x8]: m
[esp+0xc]: n

result = m^3 % n
*/
rsaenc:
    /* prologue */
    push ebx
    push esi
    push edi
    push ebp
    sub esp, 0x108 # buf1: [esp+0x84], buf2: [esp]
    /* buf1 = m*m % n */
    mov ebp, [esp+0x118+0xc]
    push esp
    mov esi, [esp+0x4+0x118+0x8]
    mov DWORD PTR [esi+124], 1
    push esi
    lea edi, [esp+0x8+0x84]
    push edi
    call modmul
    /* result = buf1*m % n */
    pop esi
    mov edi, [esp+0x8+0x118+0x4]
    push edi
    call modmul
    /* epilogue */
    add esp, 0x114
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret
