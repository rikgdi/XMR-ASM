; XMRASM : Blake2Generator (port of blake2_generator.cpp)
;
; struct Blake2Generator { uint8_t data[64]; size_t dataIndex; }  (72 bytes)
;   data[0..59]  = seed (zero-padded, max 60 bytes)
;   data[60..63] = LE32 nonce
;   dataIndex     = 64 (full, must refill before first read)
;   refill: blake2b(data, 64, data, 64)
;
; Exports:
;   b2gen_init     (rcx=gen, rdx=seed, r8=seedLen, r9d=nonce)
;   b2gen_get_byte (rcx=gen) -> eax (0..255)
;   b2gen_get_u32  (rcx=gen) -> eax (LE)

option casemap:none

PUBLIC b2gen_init, b2gen_get_byte, b2gen_get_u32

EXTERNDEF blake2b:PROC

BG_INDEX EQU 64
BG_SIZE  EQU 72

.code

; ---------------------------------------------------------------------------
; b2gen_init (rcx=gen, rdx=seed, r8=seedLen, r9d=nonce)
; ---------------------------------------------------------------------------
b2gen_init PROC
    xor eax, eax
    xor r10d, r10d
bg_z:
    mov [rcx+r10], rax
    add r10, 8
    cmp r10, 64
    jb bg_z
    mov r10, r8
    cmp r10, 60
    jbe bg_len
    mov r10, 60
bg_len:
    xor r11d, r11d
    test r10, r10
    jz bg_nonce
bg_c:
    mov al, [rdx+r11]
    mov [rcx+r11], al
    inc r11
    cmp r11, r10
    jb bg_c
bg_nonce:
    mov dword ptr [rcx+60], r9d
    mov qword ptr [rcx+BG_INDEX], 64
    ret
b2gen_init ENDP

; ---------------------------------------------------------------------------
; b2gen_get_byte (rcx=gen) -> eax
; ---------------------------------------------------------------------------
b2gen_get_byte PROC
    mov rax, [rcx+BG_INDEX]
    cmp rax, 64
    jb bgb_read
    sub rsp, 40
    mov qword ptr [rsp+32], rcx
    mov rdx, 64
    mov r8, rcx
    mov r9, 64
    call blake2b
    mov rcx, [rsp+32]
    mov qword ptr [rcx+BG_INDEX], 0
    add rsp, 40
bgb_read:
    mov rax, [rcx+BG_INDEX]
    lea r10, [rcx+rax]
    inc rax
    mov [rcx+BG_INDEX], rax
    movzx eax, byte ptr [r10]
    ret
b2gen_get_byte ENDP

; ---------------------------------------------------------------------------
; b2gen_get_u32 (rcx=gen) -> eax
; ---------------------------------------------------------------------------
b2gen_get_u32 PROC
    mov rax, [rcx+BG_INDEX]
    cmp rax, 61
    jb bgu_read
    sub rsp, 40
    mov qword ptr [rsp+32], rcx
    mov rdx, 64
    mov r8, rcx
    mov r9, 64
    call blake2b
    mov rcx, [rsp+32]
    mov qword ptr [rcx+BG_INDEX], 0
    add rsp, 40
bgu_read:
    mov rax, [rcx+BG_INDEX]
    mov eax, dword ptr [rcx+rax]
    add qword ptr [rcx+BG_INDEX], 4
    ret
b2gen_get_u32 ENDP

END
