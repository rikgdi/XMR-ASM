; XMRASM : Argon2d for RandomX cache initialization
;
; Specialized for RandomX parameters (all fixed):
;   type=Argon2_d, version=0x13, lanes=1, threads=1, outlen=0, secret=0,
;   ad=0, t_cost=3, m_cost=262144 blocks (256 MiB), salt="RandomX\x03".
; Single-lane specialization: ref_lane always 0, index_alpha simplified.
;
; Exports:
;   argon2_init_cache (rcx=memory, rdx=key, r8=keylen) -> rax 1
;
; memory must be 1024-byte aligned (256 MiB from mem_alloc is page-aligned).

option casemap:none

PUBLIC argon2_init_cache

EXTERNDEF blake2b_init:PROC
EXTERNDEF blake2b_update:PROC
EXTERNDEF blake2b_final:PROC
EXTERNDEF blake2b_long:PROC

A2_MEMORY_BLOCKS EQU 262144
A2_SEGLEN        EQU 65536
A2_LANELEN       EQU 262144
A2_PASSES        EQU 3

.data
a2_salt db "RandomX",03h

.code

; ---------------------------------------------------------------------------
; fBlaMka G macro. a/b/c/d are byte offsets from r12 (blockR base).
;   fBlaMka(x,y) = x + y + 2*((x & 0xFFFFFFFF) * (y & 0xFFFFFFFF))
;   d = rotr64(d^a, 32); b = rotr64(b^c, 24);
;   a = fBlaMka(a,b);   d = rotr64(d^a, 16);
;   c = fBlaMka(c,d);   b = rotr64(b^c, 63);
; ---------------------------------------------------------------------------
A2G macro aoff, boff, coff, doff
    mov rax, [r12+aoff]
    mov rdx, [r12+boff]
    mov r10d, eax
    mov r11d, edx
    imul r10, r11
    add r10, r10
    add rax, rdx
    add rax, r10
    mov [r12+aoff], rax
    mov rdx, [r12+doff]
    xor rdx, rax
    ror rdx, 32
    mov [r12+doff], rdx
    mov rax, [r12+coff]
    mov r10d, eax
    mov r11d, edx
    imul r10, r11
    add r10, r10
    add rax, rdx
    add rax, r10
    mov [r12+coff], rax
    mov rdx, [r12+boff]
    xor rdx, rax
    ror rdx, 24
    mov [r12+boff], rdx
    mov rax, [r12+aoff]
    mov r10d, eax
    mov r11d, edx
    imul r10, r11
    add r10, r10
    add rax, rdx
    add rax, r10
    mov [r12+aoff], rax
    mov rdx, [r12+doff]
    xor rdx, rax
    ror rdx, 16
    mov [r12+doff], rdx
    mov rax, [r12+coff]
    mov r10d, eax
    mov r11d, edx
    imul r10, r11
    add r10, r10
    add rax, rdx
    add rax, r10
    mov [r12+coff], rax
    mov rdx, [r12+boff]
    xor rdx, rax
    ror rdx, 63
    mov [r12+boff], rdx
endm

; BLAKE2_ROUND_NOMSG over 16 contiguous qwords at byte base B (column round)
A2R macro B
    A2G B+0,   B+32,  B+64,  B+96
    A2G B+8,   B+40,  B+72,  B+104
    A2G B+16,  B+48,  B+80,  B+112
    A2G B+24,  B+56,  B+88,  B+120
    A2G B+0,   B+40,  B+80,  B+120
    A2G B+8,   B+48,  B+88,  B+96
    A2G B+16,  B+56,  B+64,  B+104
    A2G B+24,  B+32,  B+72,  B+112
endm

; BLAKE2_ROUND_NOMSG over the 16 strided qwords of row-round i, base B
A2RR macro B
    A2G B+0,   B+256, B+512, B+768
    A2G B+8,   B+264, B+520, B+776
    A2G B+128, B+384, B+640, B+896
    A2G B+136, B+392, B+648, B+904
    A2G B+0,   B+264, B+640, B+904
    A2G B+8,   B+384, B+648, B+768
    A2G B+128, B+392, B+512, B+776
    A2G B+136, B+256, B+520, B+896
endm

; ---------------------------------------------------------------------------
; a2_fill_block (rcx=prev, rdx=ref, r8=next, r9d=with_xor)
;   R = ref ^ prev; tmp = R (^ next if with_xor); R = P(R) via 8 column +
;   8 row Blamka rounds; next = tmp ^ R.
; ---------------------------------------------------------------------------
a2_fill_block PROC
    push r12
    sub rsp, 2048
    mov r12, rsp                    ; R at [r12], tmp at [r12+1024]
    xor r10d, r10d
a2fb_c1:
    mov rax, [rdx+r10]
    xor rax, [rcx+r10]
    mov [r12+r10], rax
    add r10, 8
    cmp r10, 1024
    jb a2fb_c1
    xor r10d, r10d
    test r9d, r9d
    jnz a2fb_c2x
a2fb_c2:
    mov rax, [r12+r10]
    mov [r12+r10+1024], rax
    add r10, 8
    cmp r10, 1024
    jb a2fb_c2
    jmp a2fb_r1
a2fb_c2x:
    mov rax, [r12+r10]
    xor rax, [r8+r10]
    mov [r12+r10+1024], rax
    add r10, 8
    cmp r10, 1024
    jb a2fb_c2x
a2fb_r1:
    A2R 0
    A2R 128
    A2R 256
    A2R 384
    A2R 512
    A2R 640
    A2R 768
    A2R 896
    A2RR 0
    A2RR 16
    A2RR 32
    A2RR 48
    A2RR 64
    A2RR 80
    A2RR 96
    A2RR 112
    xor r10d, r10d
a2fb_st:
    mov rax, [r12+r10+1024]
    xor rax, [r12+r10]
    mov [r8+r10], rax
    add r10, 8
    cmp r10, 1024
    jb a2fb_st
    add rsp, 2048
    pop r12
    ret
a2_fill_block ENDP

; ---------------------------------------------------------------------------
; a2_fill_segment (rcx=memory, rdx=pass, r8=slice)
;   Specialized index_alpha (lanes=1 => same_lane always):
;     pass0 slice0: ref_area = i-1
;     pass0 sliceN: ref_area = slice*65536 + i - 1
;     pass>0:       ref_area = 196608 + i - 1
;   ref = ref_area-1 - ((ref_area * ((p*p)>>32)) >> 32)
;   start = pass>0 ? (slice+1)*65536 : 0; result mod 262144.
; ---------------------------------------------------------------------------
a2_fill_segment PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    mov r12, rcx                    ; memory
    mov r13d, edx                   ; pass
    mov r14d, r8d                   ; slice
    xor eax, eax                    ; starting_index
    test r13d, r13d
    jnz a2fs_sidx
    test r14d, r14d
    jnz a2fs_sidx
    mov eax, 2
a2fs_sidx:
    mov r15d, eax                   ; i
    mov ebx, r14d
    shl ebx, 16                     ; slice * 65536
    add ebx, eax                    ; curr_offset
    mov eax, ebx
    and eax, 3FFFFh                 ; curr % lane_length
    test eax, eax
    jnz a2fs_pm1
    lea esi, [ebx+262143]           ; prev = curr + lane_length - 1
    jmp a2fs_loop
a2fs_pm1:
    lea esi, [ebx-1]
a2fs_loop:
    cmp r15d, A2_SEGLEN
    jae a2fs_done
    mov eax, ebx
    and eax, 3FFFFh
    cmp eax, 1
    jne a2fs_norot
    lea esi, [ebx-1]                ; wrap: prev = curr - 1
a2fs_norot:
    ; pseudo_rand = memory[prev].v[0] (low 32 bits used)
    mov eax, esi
    shl rax, 10
    mov eax, dword ptr [r12+rax]
    ; ---- index_alpha (inline) ----
    test r13d, r13d
    jnz a2ia_p1
    test r14d, r14d
    jnz a2ia_p0n
    mov r11d, r15d
    dec r11d                        ; slice 0: index - 1
    jmp a2ia_map
a2ia_p0n:
    mov r11d, r14d
    shl r11d, 16
    add r11d, r15d
    dec r11d
    jmp a2ia_map
a2ia_p1:
    mov r11d, r15d
    add r11d, 196607                ; lane_length - segment_length - 1
a2ia_map:
    mov ecx, eax
    mul ecx                         ; edx = (p*p) >> 32
    mov ecx, edx                    ; rel
    mov eax, r11d
    mul ecx                         ; edx = (ref_area*rel) >> 32
    mov eax, r11d
    dec eax
    sub eax, edx                    ; ref
    test r13d, r13d
    jz a2ia_nostart
    mov ecx, r14d
    inc ecx
    shl ecx, 16                     ; start = (slice+1)*65536 (mod wraps ok)
    add eax, ecx
a2ia_nostart:
    and eax, 3FFFFh                 ; ref block index (lane 0)
    ; ---- fill_block(prev, ref, curr, pass != 0) ----
    mov r10d, eax
    mov eax, esi
    shl rax, 10
    lea rcx, [r12+rax]              ; prev block
    mov eax, r10d
    shl rax, 10
    lea rdx, [r12+rax]              ; ref block
    mov eax, ebx
    shl rax, 10
    lea r8, [r12+rax]               ; curr block
    xor r9d, r9d
    test r13d, r13d
    setne r9b
    call a2_fill_block
    inc r15d
    inc ebx
    inc esi
    jmp a2fs_loop
a2fs_done:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
a2_fill_segment ENDP

; ---------------------------------------------------------------------------
; argon2_init_cache (rcx=memory, rdx=key, r8=keylen) -> rax 1
;   H0 = blake2b-64(lanes||outlen||m_cost||t_cost||version||type||pwdlen||
;                   pwd||saltlen||salt||secretlen||adlen)   (all LE32)
;   block0 = blake2b_long(1024, H0||LE32(0)||LE32(0))
;   block1 = blake2b_long(1024, H0||LE32(1)||LE32(0))
;   fill 3 passes x 4 slices x 65536 blocks (Argon2d, v1.3 XOR in pass>0).
; Stack: [rsp+0..255] blake2b state, [rsp+256..327] blockhash(72),
;        [rsp+336..339] u32 scratch.
; ---------------------------------------------------------------------------
argon2_init_cache PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 352
    mov r12, rcx                    ; memory
    mov r13, rdx                    ; key
    mov r14, r8                     ; keylen
    pxor xmm0, xmm0
    movdqu xmmword ptr [rsp+256], xmm0
    movdqu xmmword ptr [rsp+272], xmm0
    movdqu xmmword ptr [rsp+288], xmm0
    movdqu xmmword ptr [rsp+304], xmm0
    movq qword ptr [rsp+320], xmm0  ; blockhash[72] = 0
    mov rcx, rsp
    mov rdx, 64
    call blake2b_init
    mov dword ptr [rsp+336], 1      ; lanes
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov dword ptr [rsp+336], 0      ; outlen
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov dword ptr [rsp+336], A2_MEMORY_BLOCKS  ; m_cost (KiB blocks)
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov dword ptr [rsp+336], A2_PASSES          ; t_cost
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov dword ptr [rsp+336], 13h    ; version
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov dword ptr [rsp+336], 0      ; type = Argon2_d
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov dword ptr [rsp+336], r14d   ; pwdlen
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov rcx, rsp
    mov rdx, r13
    mov r8, r14
    call blake2b_update             ; pwd
    mov dword ptr [rsp+336], 8      ; saltlen
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov rcx, rsp
    lea rdx, a2_salt
    mov r8, 8
    call blake2b_update             ; salt
    mov dword ptr [rsp+336], 0      ; secretlen
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov dword ptr [rsp+336], 0      ; adlen
    mov rcx, rsp
    lea rdx, [rsp+336]
    mov r8, 4
    call blake2b_update
    mov rcx, rsp
    lea rdx, [rsp+256]
    call blake2b_final              ; H0 = blockhash[0..63]
    ; block0 = H'(H0 || 0 || lane 0), block1 = H'(H0 || 1 || lane 0)
    mov rcx, r12
    mov rdx, 1024
    lea r8, [rsp+256]
    mov r9, 72
    call blake2b_long
    mov dword ptr [rsp+320], 1      ; blockhash[64] = 1
    lea rcx, [r12+1024]
    mov rdx, 1024
    lea r8, [rsp+256]
    mov r9, 72
    call blake2b_long
    ; fill: passes x slices (single lane)
    xor ebx, ebx                    ; pass
a2ic_pass:
    xor esi, esi                    ; slice
a2ic_slice:
    mov rcx, r12
    mov rdx, rbx
    mov r8, rsi
    call a2_fill_segment
    inc esi
    cmp esi, 4
    jb a2ic_slice
    inc ebx
    cmp ebx, A2_PASSES
    jb a2ic_pass
    mov eax, 1
    add rsp, 352
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
argon2_init_cache ENDP

END

