; XMRASM : dataset (V1)
;
; Native dataset initialization (no JIT):
;   executeSuperscalar   - interpret a generated superscalar program
;   initDatasetItem      - randomx::initDatasetItem (dataset.cpp)
;   randomx_alloc_dataset / randomx_free_dataset
;   randomx_get_dataset_memory / randomx_init_dataset
;
; Cache struct layout (must match src\cache.asm):
;   +0      memory (256 MiB)
;   +8      programs[8] (4200 each)
;   +33608  reciprocalCache (4096 qwords)
;   +66376  recipCount

option casemap:none

PUBLIC randomx_alloc_dataset, randomx_free_dataset, \
       randomx_get_dataset_memory, randomx_init_dataset, \
       executeSuperscalar, initDatasetItem, g_init_progress

EXTERNDEF mem_alloc:PROC
EXTERNDEF mem_free:PROC

DatasetSize    EQU 081FFFFC0h    ; 2181038016 = base 2 GiB + extra 33554368
CACHE_MEM      EQU 0
CACHE_PROGS    EQU 8
CACHE_RECIP    EQU 33608
PROG_STRIDE    EQU 4200
PROG_SIZE_OFF  EQU 4096
PROG_ADDRREG   EQU 4100
SS_IMUL_RCP    EQU 13

.data?
g_init_progress dq ?

.code

; ---------------------------------------------------------------------------
; executeSuperscalar (rcx=rl, rdx=prog, r8=recip)
;   rl[8] register file in memory; interprets prog's instruction stream.
;   Semantics match randomx::executeSuperscalar (superscalar.cpp).
; ---------------------------------------------------------------------------
executeSuperscalar PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 72
    mov r12, rcx                    ; rl
    mov r13, rdx                    ; prog
    mov r14, r8                     ; recip base
    mov r10d, dword ptr [r13+PROG_SIZE_OFF]
    lea rbx, [r13+r10*8]            ; end = prog + size*8
    mov rbp, r13                    ; cur
es_loop:
    cmp rbp, rbx
    jae es_done
    movzx eax, byte ptr [rbp]
    cmp eax, SS_IMUL_RCP
    ja  es_bad
    cmp eax, 4
    jbe es_le4
    cmp eax, 10
    jbe es_5_10
    cmp eax, 11
    je  es_imulh_r
    cmp eax, 12
    je  es_ismulh_r
    jmp es_imul_rcp
es_le4:
    cmp eax, 2
    jbe es_le2
    cmp eax, 3
    je  es_imul_r
    jmp es_iror_c
es_le2:
    cmp eax, 1
    je  es_ixor_r
    cmp eax, 2
    je  es_iadd_rs
    jmp es_isub_r
es_5_10:
    test al, 1                        ; odd (5,7,9) = IADD_C*; even = IXOR_C*
    jnz es_iadd_c
    jmp es_ixor_c
es_next:
    add rbp, 8
    jmp es_loop
es_done:
    add rsp, 72
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
es_bad:
    ud2

es_isub_r:
    movzx r10d, byte ptr [rbp+1]
    movzx r11d, byte ptr [rbp+2]
    mov rax, [r12+r10*8]
    sub rax, [r12+r11*8]
    mov [r12+r10*8], rax
    jmp es_next

es_ixor_r:
    movzx r10d, byte ptr [rbp+1]
    movzx r11d, byte ptr [rbp+2]
    mov rax, [r12+r10*8]
    xor rax, [r12+r11*8]
    mov [r12+r10*8], rax
    jmp es_next

es_iadd_rs:
    movzx r10d, byte ptr [rbp+1]
    movzx r11d, byte ptr [rbp+2]
    movzx ecx, byte ptr [rbp+3]     ; mod
    shr ecx, 2
    and ecx, 3                      ; getModShift = (mod >> 2) % 4
    mov rax, [r12+r11*8]
    shl rax, cl
    add [r12+r10*8], rax
    jmp es_next

es_imul_r:
    movzx r10d, byte ptr [rbp+1]
    movzx r11d, byte ptr [rbp+2]
    mov rax, [r12+r10*8]
    imul rax, [r12+r11*8]
    mov [r12+r10*8], rax
    jmp es_next

es_iror_c:
    movzx r10d, byte ptr [rbp+1]
    mov rax, [r12+r10*8]
    mov ecx, dword ptr [rbp+4]
    ror rax, cl
    mov [r12+r10*8], rax
    jmp es_next

es_iadd_c:
    movzx r10d, byte ptr [rbp+1]
    movsxd rax, dword ptr [rbp+4]   ; signExtend2sCompl
    add [r12+r10*8], rax
    jmp es_next

es_ixor_c:
    movzx r10d, byte ptr [rbp+1]
    movsxd rax, dword ptr [rbp+4]
    xor [r12+r10*8], rax
    jmp es_next

es_imulh_r:
    movzx r10d, byte ptr [rbp+1]
    movzx r11d, byte ptr [rbp+2]
    mov rax, [r12+r10*8]
    mul qword ptr [r12+r11*8]
    mov [r12+r10*8], rdx
    jmp es_next

es_ismulh_r:
    movzx r10d, byte ptr [rbp+1]
    movzx r11d, byte ptr [rbp+2]
    mov rax, [r12+r10*8]
    imul qword ptr [r12+r11*8]
    mov [r12+r10*8], rdx
    jmp es_next

es_imul_rcp:
    movzx r10d, byte ptr [rbp+1]
    mov eax, dword ptr [rbp+4]      ; reciprocal index
    mov rax, [r14+rax*8]
    mov r11, [r12+r10*8]
    imul r11, rax
    mov [r12+r10*8], r11
    jmp es_next
executeSuperscalar ENDP

; ---------------------------------------------------------------------------
; initDatasetItem (rcx=cache, rdx=out, r8=itemNumber)
;   matches randomx::initDatasetItem (dataset.cpp)
; ---------------------------------------------------------------------------
initDatasetItem PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 72                     ; rl[8] at [rsp..63]
    mov r12, rcx                    ; cache
    mov r13, rdx                    ; out
    mov r14, r8                     ; registerValue = itemNumber

    lea rax, [r8+1]
    mov r11, 6364136223846793005
    imul rax, r11                   ; rl[0] = (itemNumber+1) * superscalarMul0
    mov [rsp], rax
    mov rcx, 9298411001130361340
    xor rcx, rax
    mov [rsp+8], rcx
    mov rcx, 12065312585734608966
    xor rcx, rax
    mov [rsp+16], rcx
    mov rcx, 9306329213124626780
    xor rcx, rax
    mov [rsp+24], rcx
    mov rcx, 5281919268842080866
    xor rcx, rax
    mov [rsp+32], rcx
    mov rcx, 10536153434571861004
    xor rcx, rax
    mov [rsp+40], rcx
    mov rcx, 3398623926847679864
    xor rcx, rax
    mov [rsp+48], rcx
    mov rcx, 9549104520008361294
    xor rcx, rax
    mov [rsp+56], rcx

    xor r15d, r15d                  ; i = 0
di_loop:
    mov rax, [r12+CACHE_MEM]
    mov ecx, r14d
    and ecx, 3FFFFFh                 ; CacheSize/CacheLineSize - 1
    shl ecx, 6                      ; * CacheLineSize
    add rax, rcx
    prefetchnta [rax]
    mov rbx, rax                    ; mixBlock

    imul rax, r15, PROG_STRIDE
    lea rbp, [r12+rax+CACHE_PROGS]  ; &programs[i]
    mov rcx, rsp                    ; rl
    mov rdx, rbp
    lea r8, [r12+CACHE_RECIP]
    call executeSuperscalar

    mov rax, [rbx]
    xor [rsp], rax
    mov rax, [rbx+8]
    xor [rsp+8], rax
    mov rax, [rbx+16]
    xor [rsp+16], rax
    mov rax, [rbx+24]
    xor [rsp+24], rax
    mov rax, [rbx+32]
    xor [rsp+32], rax
    mov rax, [rbx+40]
    xor [rsp+40], rax
    mov rax, [rbx+48]
    xor [rsp+48], rax
    mov rax, [rbx+56]
    xor [rsp+56], rax

    mov eax, dword ptr [rbp+PROG_ADDRREG]
    mov r14, [rsp+rax*8]            ; registerValue = rl[addrReg]

    inc r15d
    cmp r15d, 8
    jb  di_loop

    mov rax, [rsp]
    mov [r13], rax
    mov rax, [rsp+8]
    mov [r13+8], rax
    mov rax, [rsp+16]
    mov [r13+16], rax
    mov rax, [rsp+24]
    mov [r13+24], rax
    mov rax, [rsp+32]
    mov [r13+32], rax
    mov rax, [rsp+40]
    mov [r13+40], rax
    mov rax, [rsp+48]
    mov [r13+48], rax
    mov rax, [rsp+56]
    mov [r13+56], rax
    add rsp, 72
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
initDatasetItem ENDP

; ---------------------------------------------------------------------------
; randomx_alloc_dataset (rcx=flags) -> rax ptr or 0
;   struct randomx_dataset { uint8_t* memory; }
; ---------------------------------------------------------------------------
randomx_alloc_dataset PROC
    push r12
    sub rsp, 48
    mov ecx, 16
    call mem_alloc
    test rax, rax
    jz  rad_fail
    mov r12, rax
    mov rcx, DatasetSize
    call mem_alloc
    test rax, rax
    jz  rad_memfail
    mov [r12], rax
    mov rax, r12
    jmp rad_out
rad_memfail:
    mov rcx, r12
    call mem_free
rad_fail:
    xor eax, eax
rad_out:
    add rsp, 48
    pop r12
    ret
randomx_alloc_dataset ENDP

; ---------------------------------------------------------------------------
; randomx_free_dataset (rcx=dataset)
; ---------------------------------------------------------------------------
randomx_free_dataset PROC
    test rcx, rcx
    jz  rfd_out
    push r12
    mov r12, rcx
    mov rcx, [r12]
    test rcx, rcx
    jz  rfd_struct
    call mem_free
rfd_struct:
    mov rcx, r12
    call mem_free
    pop r12
rfd_out:
    ret
randomx_free_dataset ENDP

; ---------------------------------------------------------------------------
; randomx_get_dataset_memory (rcx=dataset) -> rax
; ---------------------------------------------------------------------------
randomx_get_dataset_memory PROC
    mov rax, [rcx]
    ret
randomx_get_dataset_memory ENDP

; ---------------------------------------------------------------------------
; randomx_init_dataset (rcx=dataset, rdx=cache, r8=startItem, r9=itemCount)
;   writes items [start, start+count) at memory + item*64
; ---------------------------------------------------------------------------
randomx_init_dataset PROC
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov r12, [rcx]                  ; dataset memory
    imul rax, r8, 64
    add r12, rax                    ; current out
    mov r13, rdx                    ; cache
    mov r14, r8                     ; item
    lea r15, [r8+r9]                ; end
rid_loop:
    cmp r14, r15
    jae rid_done
    mov rcx, r13
    mov rdx, r12
    mov r8, r14
    call initDatasetItem
    lock inc qword ptr [g_init_progress]
    add r12, 64
    inc r14
    jmp rid_loop
rid_done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    ret
randomx_init_dataset ENDP

end
