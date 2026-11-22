; XMRASM : RandomX JIT code generator (x86-64)
;
; Port of RandomX deps/RandomX/src/jit_compiler_x86.cpp generateProgram flow
; and all 30 instruction handlers, emitting byte-identical V1 code.
;
; Exports:
;   jit_create ()                       -> rax state ptr or 0
;   jit_destroy (rcx=state)
;   jit_set_flags (rcx=state, edx=flags)
;   jit_generate_program (rcx=state, rdx=prog, r8=cfg) -> rax 1/0
;   jit_get_code (rcx=state)            -> rax code ptr
;   jit_get_codepos (rcx=state)         -> eax bytes emitted
;
; State layout (1600 bytes):
;   +0 dq code   +8 dd codePos   +12 dd vmFlags
;   +16 dd regUsage[8]           +48 dd instrOffs[384]
;
; Register convention: r12=state r13=prog r14=cfg r15=i r10=instr ptr.
; EMIT_B/EMIT_D clobber rax,rcx ; EMIT_Q clobbers rcx,rdx ; COPY_FRAG
; clobbers rax,rcx,rdx,rsi,rdi,r8.

option casemap:none

PUBLIC jit_create, jit_destroy, jit_set_flags, jit_generate_program
PUBLIC jit_get_code, jit_get_codepos

EXTERNDEF mem_alloc:PROC
EXTERNDEF mem_free:PROC
EXTERNDEF VirtualAlloc:PROC
EXTERNDEF VirtualFree:PROC
EXTERNDEF randomx_reciprocal_fast:PROC
EXTERNDEF jit_sz_prologue:DWORD
EXTERNDEF jit_sz_loopload:DWORD
EXTERNDEF jit_sz_readdataset:DWORD
EXTERNDEF jit_sz_prefetch:DWORD
EXTERNDEF jit_sz_loopstore:DWORD
EXTERNDEF jit_sz_epilogue:DWORD
EXTERNDEF randomx_program_prologue:BYTE
EXTERNDEF randomx_program_loop_load:BYTE
EXTERNDEF randomx_program_read_dataset:BYTE
EXTERNDEF randomx_prefetch_scratchpad:BYTE
EXTERNDEF randomx_program_loop_store:BYTE
EXTERNDEF randomx_program_epilogue:BYTE

JIT_CODE_SIZE       EQU 81920
JIT_STATE_SIZE      EQU 1600
JIT_PROGRAM_SIZE    EQU 256
JIT_FLAG_V2         EQU 080h
MEM_RWX_COMMIT      EQU 3000h
PAGE_EXEC_READWRITE EQU 40h
MEM_RELEASE_FLAG    EQU 8000h

JS_CODE  EQU 0
JS_POS   EQU 8
JS_FLAGS EQU 12
JS_REG   EQU 16
JS_OFFS  EQU 48
PROG_BUF EQU 128

SCRATCH_L1_MASK EQU 03FF8h
SCRATCH_L2_MASK EQU 03FFF8h
SCRATCH_L3_MASK EQU 01FFFF8h

REGISTER_NEEDS_SIB      EQU 4
REGISTER_NEEDS_DISPLACE EQU 5
STORE_L3_CONDITION      EQU 14
CONDITION_OFFSET        EQU 8

; ---------------------------------------------------------------------------
EMIT_B macro v
    mov rax, [r12 + JS_CODE]
    movsxd rcx, dword ptr [r12 + JS_POS]
    mov byte ptr [rax + rcx], v
    inc dword ptr [r12 + JS_POS]
    endm

EMIT_D macro v
    mov rax, [r12 + JS_CODE]
    movsxd rcx, dword ptr [r12 + JS_POS]
    mov dword ptr [rax + rcx], v
    add dword ptr [r12 + JS_POS], 4
    endm

EMIT_Q macro v
    mov rcx, [r12 + JS_CODE]
    movsxd rdx, dword ptr [r12 + JS_POS]
    mov qword ptr [rcx + rdx], v
    add dword ptr [r12 + JS_POS], 8
    endm

COPY_FRAG macro src_label, sz
    mov r8d, [sz]
    mov rdi, [r12 + JS_CODE]
    movsxd rax, dword ptr [r12 + JS_POS]
    add rdi, rax
    lea rsi, src_label
    mov ecx, r8d
    rep movsb
    add dword ptr [r12 + JS_POS], r8d
    endm

.code

; ---------------------------------------------------------------------------
; gen_address_reg : lea r(8+src), [r(8+src) + imm] ; and eax/ecx, L1/L2 mask
; r11d = 0 -> eax path, 1 -> ecx path
; ---------------------------------------------------------------------------
gen_address_reg PROC
    EMIT_B 41h
    EMIT_B 8Dh
    movzx r8d, byte ptr [r10 + 2]
    mov edx, 80h
    add edx, r8d
    test r11d, r11d
    jz gar_rm
    add edx, 8
gar_rm:
    EMIT_B dl
    cmp r8d, REGISTER_NEEDS_SIB
    jne gar_nosib
    EMIT_B 24h
gar_nosib:
    mov edx, dword ptr [r10 + 4]
    EMIT_D edx
    test r11d, r11d
    jnz gar_ecx
    EMIT_B 25h
    jmp gar_mask
gar_ecx:
    EMIT_B 81h
    EMIT_B 0E1h
gar_mask:
    movzx edx, byte ptr [r10 + 3]
    and edx, 3
    mov eax, SCRATCH_L2_MASK
    test edx, edx
    jz gar_emit
    mov eax, SCRATCH_L1_MASK
gar_emit:
    mov edx, eax
    EMIT_D edx
    ret
gen_address_reg ENDP

; ---------------------------------------------------------------------------
; gen_address_reg_dst : lea eax, [r(8+dst) + imm] ; and eax, L1/L2/L3 mask
; ---------------------------------------------------------------------------
gen_address_reg_dst PROC
    EMIT_B 41h
    EMIT_B 8Dh
    movzx r8d, byte ptr [r10 + 1]
    mov edx, 80h
    add edx, r8d
    EMIT_B dl
    cmp r8d, REGISTER_NEEDS_SIB
    jne gard_nosib
    EMIT_B 24h
gard_nosib:
    mov edx, dword ptr [r10 + 4]
    EMIT_D edx
    EMIT_B 25h
    movzx edx, byte ptr [r10 + 3]
    mov eax, edx
    shr eax, 4
    cmp eax, STORE_L3_CONDITION
    jb gard_l12
    mov edx, SCRATCH_L3_MASK
    EMIT_D edx
    ret
gard_l12:
    and edx, 3
    mov eax, SCRATCH_L2_MASK
    test edx, edx
    jz gard_emit
    mov eax, SCRATCH_L1_MASK
gard_emit:
    mov edx, eax
    EMIT_D edx
    ret
gen_address_reg_dst ENDP

; ---------------------------------------------------------------------------
; h_IADD_RS
; ---------------------------------------------------------------------------
h_IADD_RS PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    EMIT_B 4Fh
    EMIT_B 8Dh
    movzx edx, byte ptr [r10 + 1]
    cmp edx, REGISTER_NEEDS_DISPLACE
    je irs_disp
    lea edx, [rdx * 8 + 4]
    jmp irs_modrm
irs_disp:
    mov edx, 0ACh
irs_modrm:
    EMIT_B dl
    movzx eax, byte ptr [r10 + 3]
    shr eax, 2
    and eax, 3
    shl eax, 6
    movzx edx, byte ptr [r10 + 2]
    shl edx, 3
    or eax, edx
    movzx edx, byte ptr [r10 + 1]
    or eax, edx
    mov edx, eax
    EMIT_B dl
    cmp byte ptr [r10 + 1], REGISTER_NEEDS_DISPLACE
    jne irs_done
    mov edx, dword ptr [r10 + 4]
    EMIT_D edx
irs_done:
    ret
h_IADD_RS ENDP

; ---------------------------------------------------------------------------
; h_IADD_M
; ---------------------------------------------------------------------------
h_IADD_M PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je iam_reg
    sub rsp, 40
    xor r11d, r11d
    call gen_address_reg
    add rsp, 40
    EMIT_B 4Ch
    EMIT_B 03h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 4]
    EMIT_B dl
    EMIT_B 06h
    ret
iam_reg:
    EMIT_B 4Ch
    EMIT_B 03h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 86h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    and edx, SCRATCH_L3_MASK
    EMIT_D edx
    ret
h_IADD_M ENDP

; ---------------------------------------------------------------------------
; h_ISUB_R
; ---------------------------------------------------------------------------
h_ISUB_R PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je isr_reg
    EMIT_B 4Dh
    EMIT_B 2Bh
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    shl edx, 3
    add edx, eax
    add edx, 0C0h
    EMIT_B dl
    ret
isr_reg:
    EMIT_B 49h
    EMIT_B 81h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0E8h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    EMIT_D edx
    ret
h_ISUB_R ENDP

; ---------------------------------------------------------------------------
; h_ISUB_M
; ---------------------------------------------------------------------------
h_ISUB_M PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je ism_reg
    sub rsp, 40
    xor r11d, r11d
    call gen_address_reg
    add rsp, 40
    EMIT_B 4Ch
    EMIT_B 2Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 4]
    EMIT_B dl
    EMIT_B 06h
    ret
ism_reg:
    EMIT_B 4Ch
    EMIT_B 2Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 86h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    and edx, SCRATCH_L3_MASK
    EMIT_D edx
    ret
h_ISUB_M ENDP

; ---------------------------------------------------------------------------
; h_IMUL_R
; ---------------------------------------------------------------------------
h_IMUL_R PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je imr_reg
    EMIT_B 4Dh
    EMIT_B 0Fh
    EMIT_B 0AFh
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    shl edx, 3
    add edx, eax
    add edx, 0C0h
    EMIT_B dl
    ret
imr_reg:
    EMIT_B 4Dh
    EMIT_B 69h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + rdx + 0C0h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    EMIT_D edx
    ret
h_IMUL_R ENDP

; ---------------------------------------------------------------------------
; h_IMUL_M
; ---------------------------------------------------------------------------
h_IMUL_M PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je imm_reg
    sub rsp, 40
    xor r11d, r11d
    call gen_address_reg
    add rsp, 40
    EMIT_B 4Ch
    EMIT_B 0Fh
    EMIT_B 0AFh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 4]
    EMIT_B dl
    EMIT_B 06h
    ret
imm_reg:
    EMIT_B 4Ch
    EMIT_B 0Fh
    EMIT_B 0AFh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 86h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    and edx, SCRATCH_L3_MASK
    EMIT_D edx
    ret
h_IMUL_M ENDP

; ---------------------------------------------------------------------------
; h_IMULH_R
; ---------------------------------------------------------------------------
h_IMULH_R PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    EMIT_B 49h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    EMIT_B 49h
    EMIT_B 0F7h
    movzx edx, byte ptr [r10 + 2]
    lea edx, [rdx + 0E0h]
    EMIT_B dl
    EMIT_B 4Ch
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0C2h]
    EMIT_B dl
    ret
h_IMULH_R ENDP

; ---------------------------------------------------------------------------
; h_IMULH_M
; ---------------------------------------------------------------------------
h_IMULH_M PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je ihm_reg
    sub rsp, 40
    mov r11d, 1
    call gen_address_reg
    add rsp, 40
    EMIT_B 49h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    EMIT_B 48h
    EMIT_B 0F7h
    EMIT_B 24h
    EMIT_B 0Eh
    jmp ihm_tail
ihm_reg:
    EMIT_B 49h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    EMIT_B 48h
    EMIT_B 0F7h
    EMIT_B 0A6h
    mov edx, dword ptr [r10 + 4]
    and edx, SCRATCH_L3_MASK
    EMIT_D edx
ihm_tail:
    EMIT_B 4Ch
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0C2h]
    EMIT_B dl
    ret
h_IMULH_M ENDP

; ---------------------------------------------------------------------------
; h_ISMULH_R
; ---------------------------------------------------------------------------
h_ISMULH_R PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    EMIT_B 49h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    EMIT_B 49h
    EMIT_B 0F7h
    movzx edx, byte ptr [r10 + 2]
    lea edx, [rdx + 0E8h]
    EMIT_B dl
    EMIT_B 4Ch
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0C2h]
    EMIT_B dl
    ret
h_ISMULH_R ENDP

; ---------------------------------------------------------------------------
; h_ISMULH_M
; ---------------------------------------------------------------------------
h_ISMULH_M PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je ism2_reg
    sub rsp, 40
    mov r11d, 1
    call gen_address_reg
    add rsp, 40
    EMIT_B 49h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    EMIT_B 48h
    EMIT_B 0F7h
    EMIT_B 2Ch
    EMIT_B 0Eh
    jmp ism2_tail
ism2_reg:
    EMIT_B 49h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    EMIT_B 48h
    EMIT_B 0F7h
    EMIT_B 0AEh
    mov edx, dword ptr [r10 + 4]
    and edx, SCRATCH_L3_MASK
    EMIT_D edx
ism2_tail:
    EMIT_B 4Ch
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0C2h]
    EMIT_B dl
    ret
h_ISMULH_M ENDP

; ---------------------------------------------------------------------------
; h_IMUL_RCP : r[dst] = low64(r[dst] * floor(2^(msb+64)/imm))
; ---------------------------------------------------------------------------
h_IMUL_RCP PROC
    mov ecx, dword ptr [r10 + 4]
    test ecx, ecx
    jz ircp_done
    lea eax, [rcx - 1]
    and eax, ecx
    jz ircp_done
    sub rsp, 40
    call randomx_reciprocal_fast
    add rsp, 40
    mov r11, rax
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    EMIT_B 48h
    EMIT_B 0B8h
    EMIT_Q r11
    EMIT_B 4Ch
    EMIT_B 0Fh
    EMIT_B 0AFh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0C0h]
    EMIT_B dl
ircp_done:
    ret
h_IMUL_RCP ENDP

; ---------------------------------------------------------------------------
; h_INEG_R
; ---------------------------------------------------------------------------
h_INEG_R PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    EMIT_B 49h
    EMIT_B 0F7h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0D8h]
    EMIT_B dl
    ret
h_INEG_R ENDP

; ---------------------------------------------------------------------------
; h_IXOR_R
; ---------------------------------------------------------------------------
h_IXOR_R PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je ixr_reg
    EMIT_B 4Dh
    EMIT_B 33h
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    shl edx, 3
    add edx, eax
    add edx, 0C0h
    EMIT_B dl
    ret
ixr_reg:
    EMIT_B 49h
    EMIT_B 81h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0F0h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    EMIT_D edx
    ret
h_IXOR_R ENDP

; ---------------------------------------------------------------------------
; h_IXOR_M
; ---------------------------------------------------------------------------
h_IXOR_M PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je ixm_reg
    sub rsp, 40
    xor r11d, r11d
    call gen_address_reg
    add rsp, 40
    EMIT_B 4Ch
    EMIT_B 33h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 4]
    EMIT_B dl
    EMIT_B 06h
    ret
ixm_reg:
    EMIT_B 4Ch
    EMIT_B 33h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 86h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    and edx, SCRATCH_L3_MASK
    EMIT_D edx
    ret
h_IXOR_M ENDP

; ---------------------------------------------------------------------------
; h_IROR_R
; ---------------------------------------------------------------------------
h_IROR_R PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je iro_reg
    EMIT_B 41h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 2]
    lea edx, [rdx + 0C8h]
    EMIT_B dl
    EMIT_B 49h
    EMIT_B 0D3h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C8h]
    EMIT_B dl
    ret
iro_reg:
    EMIT_B 49h
    EMIT_B 0C1h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C8h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    and edx, 63
    EMIT_B dl
    ret
h_IROR_R ENDP

; ---------------------------------------------------------------------------
; h_IROL_R
; ---------------------------------------------------------------------------
h_IROL_R PROC
    movzx edx, byte ptr [r10 + 1]
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je iol_reg
    EMIT_B 41h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 2]
    lea edx, [rdx + 0C8h]
    EMIT_B dl
    EMIT_B 49h
    EMIT_B 0D3h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    ret
iol_reg:
    EMIT_B 49h
    EMIT_B 0C1h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    mov edx, dword ptr [r10 + 4]
    and edx, 63
    EMIT_B dl
    ret
h_IROL_R ENDP

; ---------------------------------------------------------------------------
; h_ISWAP_R
; ---------------------------------------------------------------------------
h_ISWAP_R PROC
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    cmp eax, edx
    je isw_done
    mov dword ptr [r12 + rdx * 4 + JS_REG], r15d
    mov dword ptr [r12 + rax * 4 + JS_REG], r15d
    EMIT_B 4Dh
    EMIT_B 87h
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    shl edx, 3
    add edx, eax
    add edx, 0C0h
    EMIT_B dl
isw_done:
    ret
h_ISWAP_R ENDP

; ---------------------------------------------------------------------------
; h_FSWAP_R
; ---------------------------------------------------------------------------
h_FSWAP_R PROC
    EMIT_B 66h
    EMIT_B 0Fh
    EMIT_B 0C6h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + rdx + 0C0h]
    EMIT_B dl
    EMIT_B 01h
    ret
h_FSWAP_R ENDP

; ---------------------------------------------------------------------------
; h_FADD_R
; ---------------------------------------------------------------------------
h_FADD_R PROC
    and byte ptr [r10 + 1], 3
    and byte ptr [r10 + 2], 3
    EMIT_B 66h
    EMIT_B 41h
    EMIT_B 0Fh
    EMIT_B 58h
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    shl edx, 3
    add edx, eax
    add edx, 0C0h
    EMIT_B dl
    ret
h_FADD_R ENDP

; ---------------------------------------------------------------------------
; h_FADD_M
; ---------------------------------------------------------------------------
h_FADD_M PROC
    and byte ptr [r10 + 1], 3
    sub rsp, 40
    xor r11d, r11d
    call gen_address_reg
    add rsp, 40
    EMIT_B 0F3h
    EMIT_B 44h
    EMIT_B 0Fh
    EMIT_B 0E6h
    EMIT_B 24h
    EMIT_B 06h
    EMIT_B 66h
    EMIT_B 41h
    EMIT_B 0Fh
    EMIT_B 58h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0C4h]
    EMIT_B dl
    ret
h_FADD_M ENDP

; ---------------------------------------------------------------------------
; h_FSUB_R
; ---------------------------------------------------------------------------
h_FSUB_R PROC
    and byte ptr [r10 + 1], 3
    and byte ptr [r10 + 2], 3
    EMIT_B 66h
    EMIT_B 41h
    EMIT_B 0Fh
    EMIT_B 5Ch
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    shl edx, 3
    add edx, eax
    add edx, 0C0h
    EMIT_B dl
    ret
h_FSUB_R ENDP

; ---------------------------------------------------------------------------
; h_FSUB_M
; ---------------------------------------------------------------------------
h_FSUB_M PROC
    and byte ptr [r10 + 1], 3
    sub rsp, 40
    xor r11d, r11d
    call gen_address_reg
    add rsp, 40
    EMIT_B 0F3h
    EMIT_B 44h
    EMIT_B 0Fh
    EMIT_B 0E6h
    EMIT_B 24h
    EMIT_B 06h
    EMIT_B 66h
    EMIT_B 41h
    EMIT_B 0Fh
    EMIT_B 5Ch
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0C4h]
    EMIT_B dl
    ret
h_FSUB_M ENDP

; ---------------------------------------------------------------------------
; h_FSCAL_R
; ---------------------------------------------------------------------------
h_FSCAL_R PROC
    and byte ptr [r10 + 1], 3
    EMIT_B 41h
    EMIT_B 0Fh
    EMIT_B 57h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0C7h]
    EMIT_B dl
    ret
h_FSCAL_R ENDP

; ---------------------------------------------------------------------------
; h_FMUL_R
; ---------------------------------------------------------------------------
h_FMUL_R PROC
    and byte ptr [r10 + 1], 3
    and byte ptr [r10 + 2], 3
    EMIT_B 66h
    EMIT_B 41h
    EMIT_B 0Fh
    EMIT_B 59h
    movzx eax, byte ptr [r10 + 2]
    movzx edx, byte ptr [r10 + 1]
    shl edx, 3
    add edx, eax
    add edx, 0E0h
    EMIT_B dl
    ret
h_FMUL_R ENDP

; ---------------------------------------------------------------------------
; h_FDIV_M
; ---------------------------------------------------------------------------
h_FDIV_M PROC
    and byte ptr [r10 + 1], 3
    sub rsp, 40
    xor r11d, r11d
    call gen_address_reg
    add rsp, 40
    EMIT_B 0F3h
    EMIT_B 44h
    EMIT_B 0Fh
    EMIT_B 0E6h
    EMIT_B 24h
    EMIT_B 06h
    EMIT_B 45h
    EMIT_B 0Fh
    EMIT_B 54h
    EMIT_B 0E5h
    EMIT_B 45h
    EMIT_B 0Fh
    EMIT_B 56h
    EMIT_B 0E6h
    EMIT_B 66h
    EMIT_B 41h
    EMIT_B 0Fh
    EMIT_B 5Eh
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + 0E4h]
    EMIT_B dl
    ret
h_FDIV_M ENDP

; ---------------------------------------------------------------------------
; h_FSQRT_R
; ---------------------------------------------------------------------------
h_FSQRT_R PROC
    and byte ptr [r10 + 1], 3
    EMIT_B 66h
    EMIT_B 0Fh
    EMIT_B 51h
    movzx edx, byte ptr [r10 + 1]
    lea edx, [rdx * 8 + rdx + 0E4h]
    EMIT_B dl
    ret
h_FSQRT_R ENDP

; ---------------------------------------------------------------------------
; h_CFROUND : rax=rot(r[src]); and/or 0x6000/0x9fc0; ldmxcsr
; ---------------------------------------------------------------------------
h_CFROUND PROC
    EMIT_B 49h
    EMIT_B 8Bh
    movzx edx, byte ptr [r10 + 2]
    lea edx, [rdx + 0C0h]
    EMIT_B dl
    mov eax, dword ptr [r10 + 4]
    and eax, 63
    mov edx, 13
    sub edx, eax
    and edx, 63
    test edx, edx
    jz cfr_norot
    EMIT_B 48h
    EMIT_B 0C1h
    EMIT_B 0C0h
    EMIT_B dl
cfr_norot:
    EMIT_B 25h
    EMIT_B 00h
    EMIT_B 60h
    EMIT_B 00h
    EMIT_B 00h
    EMIT_B 0Dh
    EMIT_B 0C0h
    EMIT_B 9Fh
    EMIT_B 00h
    EMIT_B 00h
    EMIT_B 89h
    EMIT_B 04h
    EMIT_B 24h
    EMIT_B 0Fh
    EMIT_B 0AEh
    EMIT_B 14h
    EMIT_B 24h
    ret
h_CFROUND ENDP

; ---------------------------------------------------------------------------
; h_CBRANCH
; ---------------------------------------------------------------------------
h_CBRANCH PROC
    movzx r8d, byte ptr [r10 + 1]
    mov eax, dword ptr [r12 + r8 * 4 + JS_REG]
    inc eax
    mov r9d, eax
    EMIT_B 49h
    EMIT_B 81h
    mov edx, r8d
    add edx, 0C0h
    EMIT_B dl
    movzx eax, byte ptr [r10 + 3]
    shr eax, 4
    add eax, CONDITION_OFFSET
    mov r11d, eax
    mov edx, dword ptr [r10 + 4]
    mov ecx, r11d
    mov eax, 1
    shl eax, cl
    or edx, eax
    mov ecx, r11d
    dec ecx
    mov eax, 1
    shl eax, cl
    not eax
    and edx, eax
    EMIT_D edx
    EMIT_B 49h
    EMIT_B 0F7h
    mov edx, r8d
    add edx, 0C0h
    EMIT_B dl
    mov ecx, r11d
    mov edx, 255
    shl edx, cl
    EMIT_D edx
    EMIT_B 0Fh
    EMIT_B 84h
    mov edx, dword ptr [r12 + r9 * 4 + JS_OFFS]
    sub edx, dword ptr [r12 + JS_POS]
    sub edx, 4
    EMIT_D edx
    xor ecx, ecx
cb_mark:
    mov dword ptr [r12 + rcx * 4 + JS_REG], r15d
    inc ecx
    cmp ecx, 8
    jb cb_mark
    ret
h_CBRANCH ENDP

; ---------------------------------------------------------------------------
; h_ISTORE
; ---------------------------------------------------------------------------
h_ISTORE PROC
    sub rsp, 40
    call gen_address_reg_dst
    add rsp, 40
    EMIT_B 4Ch
    EMIT_B 89h
    movzx edx, byte ptr [r10 + 2]
    lea edx, [rdx * 8 + 4]
    EMIT_B dl
    EMIT_B 06h
    ret
h_ISTORE ENDP

; ---------------------------------------------------------------------------
; h_NOP
; ---------------------------------------------------------------------------
h_NOP PROC
    EMIT_B 90h
    ret
h_NOP ENDP

; ---------------------------------------------------------------------------
; jit_create () -> rax state ptr or 0
; ---------------------------------------------------------------------------
jit_create PROC
    push rbx
    push rdi
    push rsi
    sub rsp, 32
    mov ecx, JIT_STATE_SIZE
    call mem_alloc
    test rax, rax
    jz jc_fail
    mov rbx, rax
    xor ecx, ecx
    mov edx, JIT_CODE_SIZE
    mov r8d, MEM_RWX_COMMIT
    mov r9d, PAGE_EXEC_READWRITE
    call VirtualAlloc
    test rax, rax
    jz jc_free
    mov [rbx + JS_CODE], rax
    mov dword ptr [rbx + JS_POS], 0
    mov dword ptr [rbx + JS_FLAGS], 0
    mov rdi, rax
    lea rsi, randomx_program_prologue
    mov ecx, [jit_sz_prologue]
    rep movsb
    mov rdi, [rbx + JS_CODE]
    mov edx, JIT_CODE_SIZE
    sub edx, [jit_sz_epilogue]
    add rdi, rdx
    lea rsi, randomx_program_epilogue
    mov ecx, [jit_sz_epilogue]
    rep movsb
    mov rax, rbx
    jmp jc_ret
jc_free:
    mov rcx, rbx
    call mem_free
jc_fail:
    xor eax, eax
jc_ret:
    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    ret
jit_create ENDP

; ---------------------------------------------------------------------------
; jit_destroy (rcx=state)
; ---------------------------------------------------------------------------
jit_destroy PROC
    push rbx
    sub rsp, 32
    test rcx, rcx
    jz jd_out
    mov rbx, rcx
    mov rcx, [rbx + JS_CODE]
    test rcx, rcx
    jz jd_state
    xor edx, edx
    mov r8d, MEM_RELEASE_FLAG
    call VirtualFree
jd_state:
    mov rcx, rbx
    call mem_free
jd_out:
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
jit_destroy ENDP

; ---------------------------------------------------------------------------
; jit_set_flags (rcx=state, edx=flags)
; ---------------------------------------------------------------------------
jit_set_flags PROC
    mov dword ptr [rcx + JS_FLAGS], edx
    ret
jit_set_flags ENDP

; ---------------------------------------------------------------------------
; jit_get_code (rcx=state) -> rax
; ---------------------------------------------------------------------------
jit_get_code PROC
    mov rax, qword ptr [rcx]
    ret
jit_get_code ENDP

; ---------------------------------------------------------------------------
; jit_get_codepos (rcx=state) -> eax
; ---------------------------------------------------------------------------
jit_get_codepos PROC
    mov eax, dword ptr [rcx + JS_POS]
    ret
jit_get_codepos ENDP

; ---------------------------------------------------------------------------
; jit_generate_program (rcx=state, rdx=prog, r8=cfg) -> rax 1/0
; ---------------------------------------------------------------------------
jit_generate_program PROC
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    sub rsp, 40
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    test dword ptr [r12 + JS_FLAGS], JIT_FLAG_V2
    jnz jgp_fail
    lea rdi, [r12 + JS_REG]
    mov eax, -1
    mov ecx, 8
    rep stosd
    mov eax, [jit_sz_prologue]
    mov dword ptr [r12 + JS_POS], eax
    mov rdi, [r12 + JS_CODE]
    add rdi, rax
    sub rdi, 48
    mov rsi, r14
    mov ecx, 16
    rep movsb
    COPY_FRAG randomx_program_loop_load, jit_sz_loopload
    xor r15d, r15d
jgp_loop:
    lea r10, [r13 + r15 * 8 + PROG_BUF]
    and byte ptr [r10 + 2], 7
    and byte ptr [r10 + 1], 7
    mov eax, dword ptr [r12 + JS_POS]
    mov dword ptr [r12 + r15 * 4 + JS_OFFS], eax
    movzx ecx, byte ptr [r10]
    lea rax, [jengine]
    call qword ptr [rax + rcx * 8]
    inc r15d
    cmp r15d, JIT_PROGRAM_SIZE
    jb jgp_loop
    EMIT_B 41h
    EMIT_B 8Bh
    mov edx, dword ptr [r14 + 24]
    add edx, 0C0h
    EMIT_B dl
    EMIT_B 41h
    EMIT_B 33h
    mov edx, dword ptr [r14 + 28]
    add edx, 0C0h
    EMIT_B dl
    COPY_FRAG randomx_program_read_dataset, jit_sz_readdataset
    EMIT_B 49h
    EMIT_B 8Bh
    mov edx, dword ptr [r14 + 16]
    add edx, 0C0h
    EMIT_B dl
    EMIT_B 49h
    EMIT_B 33h
    mov edx, dword ptr [r14 + 20]
    add edx, 0C0h
    EMIT_B dl
    COPY_FRAG randomx_prefetch_scratchpad, jit_sz_prefetch
    COPY_FRAG randomx_program_loop_store, jit_sz_loopstore
    EMIT_B 83h
    EMIT_B 0EBh
    EMIT_B 01h
    EMIT_B 0Fh
    EMIT_B 85h
    mov edx, [jit_sz_prologue]
    sub edx, dword ptr [r12 + JS_POS]
    sub edx, 4
    EMIT_D edx
    EMIT_B 0E9h
    mov edx, JIT_CODE_SIZE
    sub edx, [jit_sz_epilogue]
    sub edx, dword ptr [r12 + JS_POS]
    sub edx, 4
    EMIT_D edx
    mov eax, 1
    jmp jgp_ret
jgp_fail:
    xor eax, eax
jgp_ret:
    add rsp, 40
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    ret
jit_generate_program ENDP

; ---------------------------------------------------------------------------
; dispatch table : jengine[opcode]
; ---------------------------------------------------------------------------
.const
jengine:
    dq h_IADD_RS        ; 16
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_RS
    dq h_IADD_M         ; 7
    dq h_IADD_M
    dq h_IADD_M
    dq h_IADD_M
    dq h_IADD_M
    dq h_IADD_M
    dq h_IADD_M
    dq h_ISUB_R         ; 16
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_R
    dq h_ISUB_M         ; 7
    dq h_ISUB_M
    dq h_ISUB_M
    dq h_ISUB_M
    dq h_ISUB_M
    dq h_ISUB_M
    dq h_ISUB_M
    dq h_IMUL_R         ; 16
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_R
    dq h_IMUL_M         ; 4
    dq h_IMUL_M
    dq h_IMUL_M
    dq h_IMUL_M
    dq h_IMULH_R        ; 4
    dq h_IMULH_R
    dq h_IMULH_R
    dq h_IMULH_R
    dq h_IMULH_M        ; 1
    dq h_ISMULH_R       ; 4
    dq h_ISMULH_R
    dq h_ISMULH_R
    dq h_ISMULH_R
    dq h_ISMULH_M       ; 1
    dq h_IMUL_RCP       ; 8
    dq h_IMUL_RCP
    dq h_IMUL_RCP
    dq h_IMUL_RCP
    dq h_IMUL_RCP
    dq h_IMUL_RCP
    dq h_IMUL_RCP
    dq h_IMUL_RCP
    dq h_INEG_R         ; 2
    dq h_INEG_R
    dq h_IXOR_R         ; 15
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_R
    dq h_IXOR_M         ; 5
    dq h_IXOR_M
    dq h_IXOR_M
    dq h_IXOR_M
    dq h_IXOR_M
    dq h_IROR_R         ; 8
    dq h_IROR_R
    dq h_IROR_R
    dq h_IROR_R
    dq h_IROR_R
    dq h_IROR_R
    dq h_IROR_R
    dq h_IROR_R
    dq h_IROL_R         ; 2
    dq h_IROL_R
    dq h_ISWAP_R        ; 4
    dq h_ISWAP_R
    dq h_ISWAP_R
    dq h_ISWAP_R
    dq h_FSWAP_R        ; 4
    dq h_FSWAP_R
    dq h_FSWAP_R
    dq h_FSWAP_R
    dq h_FADD_R         ; 16
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_R
    dq h_FADD_M         ; 5
    dq h_FADD_M
    dq h_FADD_M
    dq h_FADD_M
    dq h_FADD_M
    dq h_FSUB_R         ; 16
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_R
    dq h_FSUB_M         ; 5
    dq h_FSUB_M
    dq h_FSUB_M
    dq h_FSUB_M
    dq h_FSUB_M
    dq h_FSCAL_R        ; 6
    dq h_FSCAL_R
    dq h_FSCAL_R
    dq h_FSCAL_R
    dq h_FSCAL_R
    dq h_FSCAL_R
    dq h_FMUL_R         ; 32
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FMUL_R
    dq h_FDIV_M         ; 4
    dq h_FDIV_M
    dq h_FDIV_M
    dq h_FDIV_M
    dq h_FSQRT_R        ; 6
    dq h_FSQRT_R
    dq h_FSQRT_R
    dq h_FSQRT_R
    dq h_FSQRT_R
    dq h_FSQRT_R
    dq h_CBRANCH        ; 25
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CBRANCH
    dq h_CFROUND        ; 1
    dq h_ISTORE         ; 16
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE
    dq h_ISTORE

END
