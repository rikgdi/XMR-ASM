; XMRASM : RandomX cache (structure + initialization)
;
; Port of dataset.cpp: randomx_alloc_cache / initCache (programs part).
; Layout is private to this project (not ABI-compatible with C++):
;   +0      dq  memory        ; 256 MiB Argon2d buffer
;   +8      db  programs      ; 8 * 4200 = 33600 (SuperscalarProgram)
;   +33608  dq  recipCache    ; 4096 * 8 = 32768 (u64; worst case 8 * 512)
;   +66376  dd  recipCount
;   size    =  66384
;
; Exports:
;   randomx_alloc_cache  () -> rax (cache* or 0)
;   randomx_free_cache   (rcx=cache)
;   randomx_init_cache   (rcx=cache, rdx=key, r8=keylen)
;   cache_init_programs  (rcx=cache, rdx=key, r8=keylen)
;   randomx_reciprocal   (ecx=divisor) -> rax
;     rcp = floor(2^(63+bitlen(divisor)) / divisor); divisor != 0, not a
;     power of 2 (guaranteed by the superscalar generator).
;     Clobbers rcx, rdx, r8, r9, r10, rax.

option casemap:none

PUBLIC randomx_alloc_cache, randomx_free_cache, randomx_init_cache
PUBLIC cache_init_programs, randomx_reciprocal

EXTERNDEF mem_alloc:PROC
EXTERNDEF mem_free:PROC
EXTERNDEF argon2_init_cache:PROC
EXTERNDEF b2gen_init:PROC
EXTERNDEF generateSuperscalar:PROC

CACHE_MEM    EQU 0
CACHE_PROGS  EQU 8
CACHE_RECIP  EQU 33608
CACHE_RCNT   EQU 66376
CACHE_SIZE   EQU 66384
PROG_STRIDE  EQU 4200
SS_IMUL_RCP  EQU 13

.code

; ---------------------------------------------------------------------------
; randomx_reciprocal (ecx=divisor) -> rax
;   Mirrors reciprocal.c: q = 2^63/d, r = 2^63%d, shift = bitlen(d),
;   result = (q << shift) + ((r << shift) / d)
; ---------------------------------------------------------------------------
randomx_reciprocal PROC
    mov r8d, ecx                    ; d
    mov eax, 1
    shl rax, 63
    xor edx, edx
    div rcx                         ; rax = q, rdx = r
    mov r9, rdx
    mov r10, rax
    bsr ecx, r8d
    inc ecx                         ; shift = bitlen(d)
    shl r9, cl                      ; r << shift
    mov rax, r9
    xor edx, edx
    div r8                          ; rax = (r << shift) / d
    shl r10, cl                     ; q << shift
    add rax, r10
    ret
randomx_reciprocal ENDP

; ---------------------------------------------------------------------------
; randomx_alloc_cache () -> rax
; ---------------------------------------------------------------------------
randomx_alloc_cache PROC
    push r12
    push rdi
    sub rsp, 40
    mov ecx, CACHE_SIZE
    call mem_alloc
    test rax, rax
    jz  rac_fail
    mov r12, rax
    mov rdi, r12
    mov ecx, 8298                   ; 66384 / 8
    xor eax, eax
    rep stosq
    mov ecx, 268435456              ; 256 MiB
    call mem_alloc
    test rax, rax
    jz  rac_memfail
    mov [r12+CACHE_MEM], rax
    mov rax, r12
    jmp rac_out
rac_memfail:
    mov rcx, r12
    call mem_free
rac_fail:
    xor eax, eax
rac_out:
    add rsp, 40
    pop rdi
    pop r12
    ret
randomx_alloc_cache ENDP

; ---------------------------------------------------------------------------
; randomx_free_cache (rcx=cache)
; ---------------------------------------------------------------------------
randomx_free_cache PROC
    test rcx, rcx
    jz  rfc_out
    push r12
    mov r12, rcx
    mov rcx, [r12+CACHE_MEM]
    test rcx, rcx
    jz  rfc_struct
    call mem_free
rfc_struct:
    mov rcx, r12
    call mem_free
    pop r12
rfc_out:
    ret
randomx_free_cache ENDP

; ---------------------------------------------------------------------------
; cache_init_programs (rcx=cache, rdx=key, r8=keylen)
;   Blake2Generator(key) -> 8 x generateSuperscalar -> IMUL_RCP imm ->
;   index into reciprocal cache.
; ---------------------------------------------------------------------------
cache_init_programs PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 80
    mov r12, rcx                    ; cache
    mov dword ptr [r12+CACHE_RCNT], 0
    mov rcx, rsp                    ; &gen (72 bytes at [rsp])
    xor r9d, r9d                    ; nonce = 0
    call b2gen_init
    xor r13d, r13d                  ; i
cip_lp:
    cmp r13d, 8
    jge cip_done
    imul rax, r13, PROG_STRIDE
    lea rbx, [r12+rax+CACHE_PROGS]  ; prog
    mov rcx, rbx
    mov rdx, rsp                    ; &gen
    call generateSuperscalar
    xor r14d, r14d                  ; j
cip_jl:
    movzx eax, word ptr [rbx+4096]  ; size
    cmp r14d, eax
    jge cip_next
    mov rcx, r14
    shl rcx, 3
    add rcx, rbx                    ; &prog(j)
    cmp byte ptr [rcx], SS_IMUL_RCP
    jne cip_skip
    mov ecx, dword ptr [rcx+4]      ; imm32
    call randomx_reciprocal          ; rax = rcp (rbx/r12-r15 preserved)
    mov edx, dword ptr [r12+CACHE_RCNT]
    mov rcx, r14
    shl rcx, 3
    add rcx, rbx
    mov dword ptr [rcx+4], edx      ; imm32 = reciprocal index
    mov [r12+rdx*8+CACHE_RECIP], rax
    inc dword ptr [r12+CACHE_RCNT]
cip_skip:
    inc r14d
    jmp cip_jl
cip_next:
    inc r13d
    jmp cip_lp
cip_done:
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
cache_init_programs ENDP

; ---------------------------------------------------------------------------
; randomx_init_cache (rcx=cache, rdx=key, r8=keylen)
;   Argon2d fill of 256 MiB + superscalar programs + reciprocal cache.
; ---------------------------------------------------------------------------
randomx_init_cache PROC
    push r12
    push r13
    push r14
    mov r12, rcx                    ; cache
    mov r13, rdx                    ; key
    mov r14, r8                     ; keylen
    mov rcx, [r12+CACHE_MEM]
    test rcx, rcx
    jz  rix_skip_a2
    mov rdx, r13
    mov r8, r14
    call argon2_init_cache
rix_skip_a2:
    mov rcx, r12
    mov rdx, r13
    mov r8, r14
    call cache_init_programs
    pop r14
    pop r13
    pop r12
    ret
randomx_init_cache ENDP

END
