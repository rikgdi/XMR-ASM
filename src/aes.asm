; XMRASM : RandomX AES hash/generator functions (AES-NI)
;
; Exports:
;   hashAes1Rx4        (rcx=input, rdx=inputSize, r8=hash)
;   fillAes1Rx4        (rcx=state, rdx=outputSize, r8=buffer)
;   fillAes4Rx4        (rcx=state, rdx=outputSize, r8=buffer)
;   hashAndFillAes1Rx4 (rcx=scratchpad, rdx=scratchpadSize, r8=hash, r9=fill_state)
;
; Sizes must be multiples of 64 (RandomX contract).
; Constant/memory accesses use movdqu (unaligned-safe); RandomX uses aligned
; ops on 64-byte-aligned buffers, byte results are identical.

option casemap:none

PUBLIC hashAes1Rx4, fillAes1Rx4, fillAes4Rx4, hashAndFillAes1Rx4

.data

; rx_set_int_vec_i128(a,b,c,d) = _mm_set_epi32(a,b,c,d): dword a is bits
; [127:96], dword d is bits [31:0], so memory order is (d, c, b, a).
; state0..3 = Blake2b-512("RandomX AesHash1R state")
; xkey0, xkey1 = Blake2b-256("RandomX AesHash1R xkeys")
; key0..3 = Blake2b-512("RandomX AesGenerator1R keys")
; key0..7 (4R) = Blake2b-512("RandomX AesGenerator4R keys")

aes_hash_state0 dd 92B52C0Dh, 9FA856DEh, 0CC82DB47h, 0D7983AADh
aes_hash_state1 dd 338D996Eh, 15C7B798h, 0F59E125Ah, 0ACE78057h
aes_hash_state2 dd 6A770017h, 0AE62C7D0h, 5079506Bh, 0E8A07CE4h
aes_hash_state3 dd 630A240Ch, 07AD828Dh, 79A10005h, 7E994948h

aes_hash_xkey0  dd 0F6FA8389h, 8B24949Fh, 90DC56BFh, 06890201h
aes_hash_xkey1  dd 61B263D1h, 51F4E03Ch, 0EE1043C6h, 0ED18F99Bh

aes_gen1_key0   dd 6DACA553h, 62716609h, 0DBB5552Bh, 0B4F44917h
aes_gen1_key1   dd 6D7CAF07h, 846A710Dh, 1725D378h, 0DA1DC4Eh
aes_gen1_key2   dd 3F1262F1h, 9F947EC6h, 0F4C0794Fh, 3E20E345h
aes_gen1_key3   dd 6AEF8135h, 0B1BA317Ch, 16314C88h, 49169154h

aes_gen4_key0   dd 6421AADDh, 0D1833DDBh, 2F546D2Bh, 99E5D23Fh
aes_gen4_key1   dd 0B20E3450h, 0B6913F55h, 06F79D53h, 0A5DFCDE5h
aes_gen4_key2   dd 5C3ED904h, 515E7BAFh, 0AA4679Fh, 171C02BFh
aes_gen4_key3   dd 85623763h, 0E78F5D08h, 0CD673785h, 0D8DED291h
aes_gen4_key4   dd 0B5826F73h, 0E3D6A7A6h, 3D518B6Dh, 229EFFB4h
aes_gen4_key5   dd 0C7566BF3h, 9C10B3D9h, 0E9024D4Eh, 0B272B7D2h
aes_gen4_key6   dd 0F273C9E7h, 0F765A38Bh, 2BA9660Ah, 0F63BEFA7h
aes_gen4_key7   dd 7A7CD609h, 915839DEh, 0C06D1FDh, 0C0B0762Dh

.code

; ---------------------------------------------------------------------------
; hashAes1Rx4 (rcx=input, rdx=inputSize, r8=hash)
;   state0..3 = AES_HASH_1R_STATE; per 64B: enc/dec/enc/dec from input;
;   then xkey0 round, xkey1 round; store 64B to hash.
; ---------------------------------------------------------------------------
hashAes1Rx4 PROC
    lea r9, aes_hash_state0
    movdqu xmm0, [r9]
    movdqu xmm1, [r9+16]
    movdqu xmm2, [r9+32]
    movdqu xmm3, [r9+48]
    mov rax, rcx
    add rdx, rcx                    ; end = input + inputSize
    cmp rax, rdx
    jae ha_keys
ha_loop:
    movdqu xmm4, [rax]
    movdqu xmm5, [rax+16]
    movdqu xmm6, [rax+32]
    movdqu xmm7, [rax+48]
    aesenc xmm0, xmm4
    aesdec xmm1, xmm5
    aesenc xmm2, xmm6
    aesdec xmm3, xmm7
    add rax, 64
    cmp rax, rdx
    jb ha_loop
ha_keys:
    lea rax, aes_hash_xkey0
    movdqu xmm4, [rax]
    aesenc xmm0, xmm4
    aesdec xmm1, xmm4
    aesenc xmm2, xmm4
    aesdec xmm3, xmm4
    lea rax, aes_hash_xkey1
    movdqu xmm4, [rax]
    aesenc xmm0, xmm4
    aesdec xmm1, xmm4
    aesenc xmm2, xmm4
    aesdec xmm3, xmm4
    movdqu [r8], xmm0
    movdqu [r8+16], xmm1
    movdqu [r8+32], xmm2
    movdqu [r8+48], xmm3
    ret
hashAes1Rx4 ENDP

; ---------------------------------------------------------------------------
; fillAes1Rx4 (rcx=state, rdx=outputSize, r8=buffer)
;   key0..3 = AES_GEN_1R_KEY; load state0..3; per 64B: dec/enc/dec/enc,
;   store to buffer; write state back to [rcx] after the loop.
; ---------------------------------------------------------------------------
fillAes1Rx4 PROC
    lea r9, aes_gen1_key0
    movdqu xmm8,  [r9]
    movdqu xmm9,  [r9+16]
    movdqu xmm10, [r9+32]
    movdqu xmm11, [r9+48]
    movdqu xmm4, [rcx]
    movdqu xmm5, [rcx+16]
    movdqu xmm6, [rcx+32]
    movdqu xmm7, [rcx+48]
    mov rax, r8
    add rdx, r8                     ; end = buffer + outputSize
    cmp rax, rdx
    jae f1_store
f1_loop:
    aesdec xmm4, xmm8
    aesenc xmm5, xmm9
    aesdec xmm6, xmm10
    aesenc xmm7, xmm11
    movdqu [rax], xmm4
    movdqu [rax+16], xmm5
    movdqu [rax+32], xmm6
    movdqu [rax+48], xmm7
    add rax, 64
    cmp rax, rdx
    jb f1_loop
f1_store:
    movdqu [rcx], xmm4
    movdqu [rcx+16], xmm5
    movdqu [rcx+32], xmm6
    movdqu [rcx+48], xmm7
    ret
fillAes1Rx4 ENDP

; ---------------------------------------------------------------------------
; fillAes4Rx4 (rcx=state, rdx=outputSize, r8=buffer)
;   key0..7 = AES_GEN_4R_KEY; load state0..3; per 64B: 4x dec/enc/dec/enc
;   rounds (s0/s1: key0..3, s2/s3: key4..7), store to buffer.
;   State is NOT written back (matches reference).
; ---------------------------------------------------------------------------
fillAes4Rx4 PROC
    lea r9, aes_gen4_key0
    movdqu xmm8,  [r9]
    movdqu xmm9,  [r9+16]
    movdqu xmm10, [r9+32]
    movdqu xmm11, [r9+48]
    movdqu xmm12, [r9+64]
    movdqu xmm13, [r9+80]
    movdqu xmm14, [r9+96]
    movdqu xmm15, [r9+112]
    movdqu xmm4, [rcx]
    movdqu xmm5, [rcx+16]
    movdqu xmm6, [rcx+32]
    movdqu xmm7, [rcx+48]
    mov rax, r8
    add rdx, r8
    cmp rax, rdx
    jae f4_done
f4_loop:
    aesdec xmm4, xmm8
    aesdec xmm4, xmm9
    aesdec xmm4, xmm10
    aesdec xmm4, xmm11
    aesenc xmm5, xmm8
    aesenc xmm5, xmm9
    aesenc xmm5, xmm10
    aesenc xmm5, xmm11
    aesdec xmm6, xmm12
    aesdec xmm6, xmm13
    aesdec xmm6, xmm14
    aesdec xmm6, xmm15
    aesenc xmm7, xmm12
    aesenc xmm7, xmm13
    aesenc xmm7, xmm14
    aesenc xmm7, xmm15
    movdqu [rax], xmm4
    movdqu [rax+16], xmm5
    movdqu [rax+32], xmm6
    movdqu [rax+48], xmm7
    add rax, 64
    cmp rax, rdx
    jb f4_loop
f4_done:
    ret
fillAes4Rx4 ENDP

; ---------------------------------------------------------------------------
; hashAndFillAes1Rx4 (rcx=scratchpad, rdx=scratchpadSize, r8=hash,
;                     r9=fill_state)
;   hash lanes start at AES_HASH_1R_STATE, fill lanes at [fill_state].
;   Two-pass loop (pass 1: [0, size-4096), pass 2: remainder; sizes < 4096
;   run only pass 2) with prefetcht0 pipelining, matching the reference:
;   per 64B: hash lanes read, fill lanes (dec/enc/dec/enc, key0..3) written
;   back; then fill_state stored back, xkey0/xkey1 rounds on hash lanes,
;   64B hash stored.
; ---------------------------------------------------------------------------
hashAndFillAes1Rx4 PROC
    push rbx
    push rsi
    push r12
    push r13
    push r14
    push r15
    mov rbx, r9                     ; fill_state ptr
    mov rsi, r8                     ; hash ptr
    lea r9, aes_hash_state0
    movdqu xmm0, [r9]
    movdqu xmm1, [r9+16]
    movdqu xmm2, [r9+32]
    movdqu xmm3, [r9+48]
    lea r9, aes_gen1_key0
    movdqu xmm8,  [r9]
    movdqu xmm9,  [r9+16]
    movdqu xmm10, [r9+32]
    movdqu xmm11, [r9+48]
    movdqu xmm4, [rbx]
    movdqu xmm5, [rbx+16]
    movdqu xmm6, [rbx+32]
    movdqu xmm7, [rbx+48]
    mov r15, rcx                    ; base
    mov r12, rcx                    ; ptr
    lea r13, [rcx+rdx-4096]         ; end = base + size - 4096
    lea r14, [rcx+4096]             ; prefetchPtr = base + 4096
    mov eax, 2
hf_outer:
    cmp r12, r13
    jae hf_next
hf_loop:
    movdqu xmm12, [r12]
    aesenc xmm0, xmm12
    movdqu xmm12, [r12+16]
    aesdec xmm1, xmm12
    movdqu xmm12, [r12+32]
    aesenc xmm2, xmm12
    movdqu xmm12, [r12+48]
    aesdec xmm3, xmm12
    aesdec xmm4, xmm8
    aesenc xmm5, xmm9
    aesdec xmm6, xmm10
    aesenc xmm7, xmm11
    movdqu [r12], xmm4
    movdqu [r12+16], xmm5
    movdqu [r12+32], xmm6
    movdqu [r12+48], xmm7
    prefetcht0 [r14]
    add r12, 64
    add r14, 64
    cmp r12, r13
    jb hf_loop
hf_next:
    mov r14, r15
    add r13, 4096
    dec eax
    jnz hf_outer
    movdqu [rbx], xmm4
    movdqu [rbx+16], xmm5
    movdqu [rbx+32], xmm6
    movdqu [rbx+48], xmm7
    lea r9, aes_hash_xkey0
    movdqu xmm12, [r9]
    aesenc xmm0, xmm12
    aesdec xmm1, xmm12
    aesenc xmm2, xmm12
    aesdec xmm3, xmm12
    lea r9, aes_hash_xkey1
    movdqu xmm12, [r9]
    aesenc xmm0, xmm12
    aesdec xmm1, xmm12
    aesenc xmm2, xmm12
    aesdec xmm3, xmm12
    movdqu [rsi], xmm0
    movdqu [rsi+16], xmm1
    movdqu [rsi+32], xmm2
    movdqu [rsi+48], xmm3
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rbx
    ret
hashAndFillAes1Rx4 ENDP

END
