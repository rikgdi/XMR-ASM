; XMRASM : BLAKE2b (RFC 7693 reference implementation)
;
; Exports:
;   blake2b        (rcx=out, rdx=outlen, r8=in, r9=inlen)  one-shot, unkeyed
;   blake2b_init   (rcx=state, rdx=outlen)
;   blake2b_update (rcx=state, rdx=in, r8=inlen)
;   blake2b_final  (rcx=state, rdx=out)   outlen comes from state
;   blake2b_long   (rcx=out, rdx=outlen, r8=in, r9=inlen)
;
; state layout (BLAKE2B_STATE_SIZE = 256 bytes):
;   +0   h   dq 8
;   +64  t   dq 2
;   +80  f   dq 2
;   +96  buf db 128
;   +224 buflen dd
;   +228 outlen db
;   +229 last_node db

option casemap:none

PUBLIC blake2b, blake2b_init, blake2b_update, blake2b_final, blake2b_long

BLAKE2B_STATE_SIZE EQU 256
BLAKE2B_BLOCK      EQU 128
B_H                EQU 0
B_T                EQU 64
B_F                EQU 80
B_BUF              EQU 96
B_BUFLEN           EQU 224
B_OUTLEN           EQU 228

.data
blake2b_IV:
    dq 6A09E667F3BCC908h, 0BB67AE8584CAA73Bh
    dq 3C6EF372FE94F82Bh, 0A54FF53A5F1D36F1h
    dq 510E527FADE682D1h, 9B05688C2B3E6C1Fh
    dq 1F83D9ABFB41BD6Bh, 5BE0CD19137E2179h

; ---------------------------------------------------------------------------
; G mixing macro
;   va..vd : byte offsets of v registers on stack (v[i] = 8*i)
;   s0,s1  : constant m indices from the sigma table for this round
;   r15 = &v[0], r14 = &m[0]
; ---------------------------------------------------------------------------
GG MACRO va, vb, vc, vd, s0, s1
    mov rax, qword ptr [r14+s0*8]
    add rax, qword ptr [r15+vb]
    add rax, qword ptr [r15+va]
    mov qword ptr [r15+va], rax
    mov rax, qword ptr [r15+vd]
    xor rax, qword ptr [r15+va]
    ror rax, 32
    mov qword ptr [r15+vd], rax
    mov rax, qword ptr [r15+vc]
    add rax, qword ptr [r15+vd]
    mov qword ptr [r15+vc], rax
    mov rax, qword ptr [r15+vb]
    xor rax, qword ptr [r15+vc]
    ror rax, 24
    mov qword ptr [r15+vb], rax

    mov rax, qword ptr [r14+s1*8]
    add rax, qword ptr [r15+vb]
    add rax, qword ptr [r15+va]
    mov qword ptr [r15+va], rax
    mov rax, qword ptr [r15+vd]
    xor rax, qword ptr [r15+va]
    ror rax, 16
    mov qword ptr [r15+vd], rax
    mov rax, qword ptr [r15+vc]
    add rax, qword ptr [r15+vd]
    mov qword ptr [r15+vc], rax
    mov rax, qword ptr [r15+vb]
    xor rax, qword ptr [r15+vc]
    ror rax, 63
    mov qword ptr [r15+vb], rax
ENDM

; ROUND macro: 16 sigma values (m indices)
ROUND MACRO s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15
    GG 0,  32, 64, 96,  s0, s1
    GG 8,  40, 72, 104, s2, s3
    GG 16, 48, 80, 112, s4, s5
    GG 24, 56, 88, 120, s6, s7
    GG 0,  40, 80, 120, s8, s9
    GG 8,  48, 88, 96,  s10,s11
    GG 16, 56, 64, 104, s12,s13
    GG 24, 32, 72, 112, s14,s15
ENDM

.code

; ---------------------------------------------------------------------------
; blake2b_compress (rcx=state, rdx=block)
;   clobbers rax, rcx, rdx, rsi, rdi, r8-r14, r15 (except we don't use them
;   across calls); preserves rbx, rbp, r12-r15? -> preserves rbx/rbp only.
; ---------------------------------------------------------------------------
blake2b_compress PROC
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 304                    ; [rsp..127]=m[16], [rsp+128..255]=v[16],
                                    ; + 48 bytes spare/alignment
    ; ---- load m ----
    xor eax, eax
@@:
    mov r8, qword ptr [rdx+rax*8]
    mov qword ptr [rsp+rax*8], r8
    inc eax
    cmp eax, 16
    jb @B

    ; ---- load v ----
    lea r15, [rsp+128]
    xor eax, eax
@@:
    mov r8, qword ptr [rcx+rax*8]
    mov qword ptr [r15+rax*8], r8
    inc eax
    cmp eax, 8
    jb @B
    lea r14, blake2b_IV
    xor eax, eax
@@:
    mov r8, qword ptr [r14+rax*8]
    mov qword ptr [r15+rax*8+64], r8
    inc eax
    cmp eax, 4
    jb @B
    mov r8, qword ptr [r14+32]
    xor r8, qword ptr [rcx+B_T+0]
    mov qword ptr [r15+96], r8
    mov r8, qword ptr [r14+40]
    xor r8, qword ptr [rcx+B_T+8]
    mov qword ptr [r15+104], r8
    mov r8, qword ptr [r14+48]
    xor r8, qword ptr [rcx+B_F+0]
    mov qword ptr [r15+112], r8
    mov r8, qword ptr [r14+56]
    xor r8, qword ptr [rcx+B_F+8]
    mov qword ptr [r15+120], r8

    lea r14, [rsp+0]                ; r14 = &m[0]

    ; ---- 12 rounds, fully unrolled ----
    ROUND 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    ROUND 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3
    ROUND 11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4
    ROUND 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8
    ROUND 9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13
    ROUND 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9
    ROUND 12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11
    ROUND 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10
    ROUND 6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5
    ROUND 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0
    ROUND 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    ROUND 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3

    ; ---- h[i] ^= v[i] ^ v[i+8] ----
    xor eax, eax
@@:
    mov r8, qword ptr [rcx+rax*8]
    mov r9, qword ptr [r15+rax*8]
    xor r9, qword ptr [r15+rax*8+64]
    xor r8, r9
    mov qword ptr [rcx+rax*8], r8
    inc eax
    cmp eax, 8
    jb @B

    add rsp, 304
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
blake2b_compress ENDP

; ---------------------------------------------------------------------------
; blake2b_init (rcx=state, rdx=outlen)
; ---------------------------------------------------------------------------
blake2b_init PROC
    push rbx
    sub rsp, 40
    mov rbx, rcx
    ; zero whole state
    xor eax, eax
    mov ecx, BLAKE2B_STATE_SIZE/8
    mov rdi, rbx
    push rdx
    rep stosq
    pop rdx
    ; h = IV
    lea rsi, blake2b_IV
    mov rdi, rbx
    mov ecx, 8
    rep movsq
    ; h[0] ^= parameter block (unkeyed): digest_length=dl, key_length=0,
    ; fanout=1, depth=1, remaining param bytes are zero
    movzx eax, dl
    or rax, 01010000h
    xor qword ptr [rbx], rax
    mov byte ptr [rbx+B_OUTLEN], dl
    add rsp, 40
    pop rbx
    ret
blake2b_init ENDP

; ---------------------------------------------------------------------------
; blake2b_update (rcx=state, rdx=in, r8=inlen)
; ---------------------------------------------------------------------------
blake2b_update PROC
    push rbx
    push rbp
    sub rsp, 40
    mov rbx, rcx                    ; state
    mov rbp, rdx                    ; pin
    mov r9, r8                      ; inlen
    test r9, r9
    jz bu_done
    mov eax, dword ptr [rbx+B_BUFLEN]
    mov r10, rax
    add r10, r9
    cmp r10, BLAKE2B_BLOCK
    jbe bu_copy
    ; fill = 128 - buflen
    mov r11, BLAKE2B_BLOCK
    sub r11, rax                    ; r11 = fill
    lea rdi, [rbx+B_BUF]
    add rdi, rax
    mov rsi, rbp
    mov rcx, r11
    push r11
    push r9
    rep movsb
    pop r9
    pop r11
    ; t += 128 ; compress(buf)
    mov rax, qword ptr [rbx+B_T]
    add rax, BLAKE2B_BLOCK
    mov qword ptr [rbx+B_T], rax
    adc qword ptr [rbx+B_T+8], 0
    mov rcx, rbx
    lea rdx, [rbx+B_BUF]
    push r9
    push r11
    push rbp
    call blake2b_compress
    pop rbp
    pop r11
    pop r9
    mov dword ptr [rbx+B_BUFLEN], 0
    sub r9, r11
    add rbp, r11
bu_whole:
    cmp r9, BLAKE2B_BLOCK
    jbe bu_copy
    mov rax, qword ptr [rbx+B_T]
    add rax, BLAKE2B_BLOCK
    mov qword ptr [rbx+B_T], rax
    adc qword ptr [rbx+B_T+8], 0
    mov rcx, rbx
    mov rdx, rbp
    push r9
    push rbp
    call blake2b_compress
    pop rbp
    pop r9
    sub r9, BLAKE2B_BLOCK
    add rbp, BLAKE2B_BLOCK
    jmp bu_whole
bu_copy:
    mov eax, dword ptr [rbx+B_BUFLEN]
    lea rdi, [rbx+B_BUF]
    add rdi, rax
    mov rsi, rbp
    mov rcx, r9
    rep movsb
    add dword ptr [rbx+B_BUFLEN], r9d
bu_done:
    xor eax, eax
    add rsp, 40
    pop rbp
    pop rbx
    ret
blake2b_update ENDP

; ---------------------------------------------------------------------------
; blake2b_final (rcx=state, rdx=out)
; ---------------------------------------------------------------------------
blake2b_final PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 112
    mov rbx, rcx
    mov r11, rdx                    ; save out pointer
    ; t += buflen
    mov edx, dword ptr [rbx+B_BUFLEN]
    mov rax, qword ptr [rbx+B_T]
    add rax, rdx
    mov qword ptr [rbx+B_T], rax
    adc qword ptr [rbx+B_T+8], 0
    ; f0 = all ones
    mov rax, -1
    mov qword ptr [rbx+B_F+0], rax
    ; pad buffer
    mov eax, dword ptr [rbx+B_BUFLEN]
    lea rdi, [rbx+B_BUF]
    add rdi, rax
    mov ecx, BLAKE2B_BLOCK
    sub ecx, eax
    xor eax, eax
    rep stosb
    mov rcx, rbx
    lea rdx, [rbx+B_BUF]
    call blake2b_compress
    ; write first outlen bytes of h to out
    movzx ecx, byte ptr [rbx+B_OUTLEN]
    lea rsi, [rbx+B_H]
    mov rdi, r11
    rep movsb
    add rsp, 112
    pop rdi
    pop rsi
    pop rbx
    ret
blake2b_final ENDP

; ---------------------------------------------------------------------------
; blake2b (rcx=out, rdx=outlen, r8=in, r9=inlen) : one-shot unkeyed
; ---------------------------------------------------------------------------
blake2b PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 320
    mov r12, rcx                    ; out
    mov r13d, edx                   ; outlen
    ; init(state, outlen)
    mov rcx, rsp
    mov rdx, r13
    call blake2b_init
    ; update(state, in, inlen)
    mov rcx, rsp
    mov rdx, r8
    mov r8, r9
    call blake2b_update
    ; final(state, out)
    mov rcx, rsp
    mov rdx, r12
    call blake2b_final
    add rsp, 320
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
blake2b ENDP

; ---------------------------------------------------------------------------
; blake2b_long (rcx=out, rdx=outlen, r8=in, r9=inlen) : argon2 H'
;   outlen <= 64 : blake2b(out, outlen, le32(outlen) || in)
;   otherwise    : blake2b-64 over le32(outlen)||in into out[0..63],
;                  then repeatedly blake2b-64 over the previous 64 output
;                  bytes until 1040 remain, final chunk blake2b-rlen.
; ---------------------------------------------------------------------------
blake2b_long PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 336                    ; state(256) + le32(4) + vbuf(64) + pad
    mov r12, rcx                    ; out ptr
    mov r13, rdx                    ; outlen
    mov r14, r8                     ; in ptr
    mov r15, r9                     ; inlen
    cmp r13, 64
    ja b2bl_big
    ; ---- small: H'(X) = H^outlen(le32(outlen) || X) ----
    mov rcx, rsp
    mov rdx, r13
    call blake2b_init
    mov dword ptr [rsp+256], r13d   ; le32(outlen)
    mov rcx, rsp
    lea rdx, [rsp+256]
    mov r8, 4
    call blake2b_update
    mov rcx, rsp
    mov rdx, r14
    mov r8, r15
    call blake2b_update
    mov rcx, rsp
    mov rdx, r12
    call blake2b_final
    jmp b2bl_done
b2bl_big:
    ; V1 = H^64(le32(outlen) || X); emit V1[0..31];
    ; while toproduce > 64: V = H^64(V); emit V[0..31];
    ; final: H^toproduce(V) emitted (toproduce <= 64).
    mov rcx, rsp
    mov rdx, 64
    call blake2b_init
    mov dword ptr [rsp+256], r13d   ; le32(outlen)
    mov rcx, rsp
    lea rdx, [rsp+256]
    mov r8, 4
    call blake2b_update
    mov rcx, rsp
    mov rdx, r14
    mov r8, r15
    call blake2b_update
    mov rcx, rsp
    lea rdx, [rsp+264]              ; V1
    call blake2b_final
    mov rax, [rsp+264]
    mov [r12], rax
    mov rax, [rsp+272]
    mov [r12+8], rax
    mov rax, [rsp+280]
    mov [r12+16], rax
    mov rax, [rsp+288]
    mov [r12+24], rax
    add r12, 32
    sub r13d, 32                    ; toproduce = outlen - 32
b2bl_loop:
    cmp r13d, 64
    jbe b2bl_last
    mov rcx, rsp
    mov rdx, 64
    call blake2b_init
    mov rcx, rsp
    lea rdx, [rsp+264]              ; in = previous V
    mov r8, 64
    call blake2b_update
    mov rcx, rsp
    lea rdx, [rsp+264]              ; out = same buffer
    call blake2b_final
    mov rax, [rsp+264]
    mov [r12], rax
    mov rax, [rsp+272]
    mov [r12+8], rax
    mov rax, [rsp+280]
    mov [r12+16], rax
    mov rax, [rsp+288]
    mov [r12+24], rax
    add r12, 32
    sub r13d, 32
    jmp b2bl_loop
b2bl_last:
    mov rcx, rsp
    mov rdx, r13                    ; rlen = toproduce <= 64
    call blake2b_init
    mov rcx, rsp
    lea rdx, [rsp+264]
    mov r8, 64
    call blake2b_update
    mov rcx, rsp
    mov rdx, r12
    call blake2b_final
b2bl_done:
    xor eax, eax
    add rsp, 336
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
blake2b_long ENDP

END
