; XMRASM : superscalar program generator (port of superscalar.cpp)
;
; SuperscalarProgram layout (stride 4200):
;   +0     programBuffer[512] (8 bytes per instruction) = 4096
;   +4096  size            (dword)
;   +4100  addrReg         (dword)
;   +4104  cpuLatencies[8] (dwords)
;   +4136  asicLatencies[8](dwords)
;   +4168  cpuLatency      (dword)
;   +4172  asicLatency     (dword)
;   +4176  codeSize        (dword)
;   +4180  macroOps        (dword)
;   +4184  decodeCycles    (dword)
;   +4188  mulCount        (dword)
;
; Output Instruction: opcode,dst,src,mod (u8 each) + imm32 (u32)
;
; Blake2Generator layout: data[64] + dataIndex (qword) = 72 bytes
;
; Exports:
;   generateSuperscalar (rcx=prog, rdx=gen)

option casemap:none

PUBLIC generateSuperscalar

EXTERNDEF b2gen_get_byte:PROC
EXTERNDEF b2gen_get_u32:PROC

; ---- SuperscalarInstructionType -----------------------------------------
SS_ISUB_R   EQU 0
SS_IXOR_R   EQU 1
SS_IADD_RS  EQU 2
SS_IMUL_R   EQU 3
SS_IROR_C   EQU 4
SS_IADD_C7  EQU 5
SS_IXOR_C7  EQU 6
SS_IADD_C8  EQU 7
SS_IXOR_C8  EQU 8
SS_IADD_C9  EQU 9
SS_IXOR_C9  EQU 10
SS_IMULH_R  EQU 11
SS_ISMULH_R EQU 12
SS_IMUL_RCP EQU 13
SS_NOP      EQU -1

; ---- MacroOp table indices ---------------------------------------------
MP_SUB_RR   EQU 0
MP_XOR_RR   EQU 1
MP_LEA_SIB  EQU 2
MP_IMUL_RR  EQU 3
MP_ROR_RI   EQU 4
MP_ADD_RI   EQU 5
MP_XOR_RI   EQU 6
MP_MOV_RR   EQU 7
MP_MUL_R    EQU 8
MP_IMUL_R   EQU 9
MP_MOV_RI64 EQU 10
MP_IMUL_RRD EQU 11

; ---- SuperscalarInstructionInfo layout (stride 40) -----------------------
INFO_TYPE   EQU 0
INFO_OPS    EQU 4
INFO_LAT    EQU 8
INFO_RETOP  EQU 12
INFO_DSTOP  EQU 16
INFO_SRCOP  EQU 20
INFO_MOPIDX EQU 24            ; 3 dwords: mop indices
INFO_SIZE   EQU 40

; ---- MacroOp layout (stride 20) ------------------------------------------
MOP_SIZE  EQU 0
MOP_LAT   EQU 4
MOP_UOP1  EQU 8
MOP_UOP2  EQU 12
MOP_DEP   EQU 16

; ---- DecoderBuffer layout (stride 24) ------------------------------------
DB_INDEX  EQU 0
DB_SIZE   EQU 4
DB_COUNTS EQU 8               ; up to 4 dwords

; ---- currentInstruction layout (40 bytes) --------------------------------
CI_INFO   EQU 0
CI_SRC    EQU 8
CI_DST    EQU 12
CI_MOD    EQU 16
CI_IMM    EQU 20
CI_GROUP  EQU 24
CI_GPAR   EQU 28
CI_REUSE  EQU 32
CI_GPISRC EQU 36

; ---- stack scalars in generateSuperscalar -------------------------------
S_MOPIDX  EQU 736
S_CODESZ  EQU 740
S_MOPCNT  EQU 744
S_CYCLE   EQU 748
S_DEP     EQU 752
S_RETIRE  EQU 756
S_SAT     EQU 760
S_PROGSZ  EQU 764
S_MULCNT  EQU 768
S_THROW   EQU 772
S_DECYC   EQU 776
S_TOPCYC  EQU 780
S_SCHED   EQU 784
S_FWD     EQU 788
S_BUFIDX  EQU 792
S_FETCHTY EQU 796
S_SLOTSZ  EQU 800
S_ISLAST  EQU 804
S_MOPPTR  EQU 808

.data

; ---- MacroOps: {size, latency, uop1, uop2, dependent} --------------------
ss_mops:
    dd 3, 1, 7, 0, 0          ; MP_SUB_RR   sub r,r   p015
    dd 3, 1, 7, 0, 0          ; MP_XOR_RR   xor r,r   p015
    dd 4, 1, 3, 0, 0          ; MP_LEA_SIB  lea       p01
    dd 4, 3, 2, 0, 0          ; MP_IMUL_RR  imul r,r  p1
    dd 4, 1, 5, 0, 0          ; MP_ROR_RI   ror r,i   p05
    dd 7, 1, 7, 0, 0          ; MP_ADD_RI   add r,i   p015
    dd 7, 1, 7, 0, 0          ; MP_XOR_RI   xor r,i   p015
    dd 3, 0, 0, 0, 0          ; MP_MOV_RR   mov r,r   (eliminated)
    dd 3, 4, 2, 4, 0          ; MP_MUL_R    mul r     p1+p5
    dd 3, 4, 2, 4, 0          ; MP_IMUL_R   imul r    p1+p5
    dd 10, 1, 7, 0, 0         ; MP_MOV_RI64 mov r,i64 p015
    dd 4, 3, 2, 0, 1          ; MP_IMUL_RRD imul r,r  p1 (dependent)

; ---- SuperscalarInstructionInfo: {type, opsCount, latency,
;      resultOp, dstOp, srcOp, mopIdx[3], pad} (40 bytes each) ------------
ss_infos:
info_ISUB_R label byte
    dd SS_ISUB_R, 1, 1, 0, 0, 0,  MP_SUB_RR, 0, 0, 0
info_IXOR_R label byte
    dd SS_IXOR_R, 1, 1, 0, 0, 0,  MP_XOR_RR, 0, 0, 0
info_IADD_RS label byte
    dd SS_IADD_RS, 1, 1, 0, 0, 0, MP_LEA_SIB, 0, 0, 0
info_IMUL_R label byte
    dd SS_IMUL_R, 1, 3, 0, 0, 0,  MP_IMUL_RR, 0, 0, 0
info_IROR_C label byte
    dd SS_IROR_C, 1, 1, 0, 0, -1, MP_ROR_RI, 0, 0, 0
info_IADD_C7 label byte
    dd SS_IADD_C7, 1, 1, 0, 0, -1, MP_ADD_RI, 0, 0, 0
info_IXOR_C7 label byte
    dd SS_IXOR_C7, 1, 1, 0, 0, -1, MP_XOR_RI, 0, 0, 0
info_IADD_C8 label byte
    dd SS_IADD_C8, 1, 1, 0, 0, -1, MP_ADD_RI, 0, 0, 0
info_IXOR_C8 label byte
    dd SS_IXOR_C8, 1, 1, 0, 0, -1, MP_XOR_RI, 0, 0, 0
info_IADD_C9 label byte
    dd SS_IADD_C9, 1, 1, 0, 0, -1, MP_ADD_RI, 0, 0, 0
info_IXOR_C9 label byte
    dd SS_IXOR_C9, 1, 1, 0, 0, -1, MP_XOR_RI, 0, 0, 0
info_IMULH_R label byte
    dd SS_IMULH_R, 3, 4, 1, 0, 1, MP_MOV_RR, MP_MUL_R, MP_MOV_RR, 0
info_ISMULH_R label byte
    dd SS_ISMULH_R, 3, 4, 1, 0, 1, MP_MOV_RR, MP_IMUL_R, MP_MOV_RR, 0
info_IMUL_RCP label byte
    dd SS_IMUL_RCP, 2, 4, 1, 1, -1, MP_MOV_RI64, MP_IMUL_RRD, 0, 0
info_NOP label byte
    dd SS_NOP, 0, 0, 0, 0, 0, 0, 0, 0, 0

; ---- DecoderBuffers: {index, size, counts[4]} (24 bytes each) ------------
ss_b484:
    dd 0, 3, 4, 8, 4, 0
ss_b7333:
    dd 1, 4, 7, 3, 3, 3
ss_b3733:
    dd 2, 4, 3, 7, 3, 3
ss_b493:
    dd 3, 3, 4, 9, 3, 0
ss_b4444:
    dd 4, 4, 4, 4, 4, 4
ss_b3310:
    dd 5, 3, 3, 3, 10, 0

ss_decode_buffers:
    dq ss_b484, ss_b7333, ss_b3733, ss_b493

; ---- slot tables ---------------------------------------------------------
ss_slot3:
    dq info_ISUB_R, info_IXOR_R
ss_slot3L:
    dq info_ISUB_R, info_IXOR_R, info_IMULH_R, info_ISMULH_R
ss_slot4:
    dq info_IROR_C, info_IADD_RS
ss_slot7:
    dq info_IXOR_C7, info_IADD_C7
ss_slot8:
    dq info_IXOR_C8, info_IADD_C8
ss_slot9:
    dq info_IXOR_C9, info_IADD_C9

.code

; ===========================================================================
; ss_uop (ecx=uop, edx=cycle, r8d=commit, r9=portBusy) -> eax
;   portBusy[cycle][3] byte map: scan P5 -> P0 -> P1 from `cycle` to 173.
; ===========================================================================
ss_uop PROC
    mov eax, edx
ssu_loop:
    cmp eax, 174
    jge ssu_fail
    lea r10, [r9+rax*2]
    add r10, rax                    ; r10 = portBusy + cycle*3
    test cl, 4
    jz  ssu_no5
    cmp byte ptr [r10+2], 0
    jne ssu_no5
    test r8d, r8d
    jz  ssu_ret
    mov byte ptr [r10+2], cl
    ret
ssu_no5:
    test cl, 1
    jz  ssu_no0
    cmp byte ptr [r10], 0
    jne ssu_no0
    test r8d, r8d
    jz  ssu_ret
    mov byte ptr [r10], cl
    ret
ssu_no0:
    test cl, 2
    jz  ssu_next
    cmp byte ptr [r10+1], 0
    jne ssu_next
    test r8d, r8d
    jz  ssu_ret
    mov byte ptr [r10+1], cl
    ret
ssu_next:
    inc eax
    jmp ssu_loop
ssu_fail:
    mov eax, -1
ssu_ret:
    ret
ss_uop ENDP

; ===========================================================================
; ss_mop (ecx=mop, rdx=(depCycle<<32)|cycle, r8d=commit, r9=portBusy) -> eax
;   Port of scheduleMop<commit>.
; ===========================================================================
ss_mop PROC
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov r12, rcx                    ; mop
    mov r13, r9                     ; portBusy
    mov r14d, r8d                   ; commit
    mov eax, edx                    ; cycle
    shr rdx, 32                     ; depCycle
    cmp dword ptr [r12+MOP_DEP], 0
    je  ssm_udep
    cmp eax, edx
    jge ssm_udep
    mov eax, edx
ssm_udep:
    cmp dword ptr [r12+MOP_UOP1], 0
    jne ssm_notelim
    jmp ssm_done                    ; eliminated: return cycle
ssm_notelim:
    cmp dword ptr [r12+MOP_UOP2], 0
    jne ssm_two
    ; simple macro-op: single uOP
    mov ecx, [r12+MOP_UOP1]
    mov edx, eax
    mov r8d, r14d
    mov r9, r13
    call ss_uop
    jmp ssm_done
ssm_two:
    mov r15d, eax                   ; c = cycle
ssm_cloop:
    cmp r15d, 174
    jge ssm_fail
    mov ecx, [r12+MOP_UOP1]
    mov edx, r15d
    xor r8d, r8d
    mov r9, r13
    call ss_uop
    mov [rsp+32], eax               ; cycle1
    mov ecx, [r12+MOP_UOP2]
    mov edx, r15d
    xor r8d, r8d
    mov r9, r13
    call ss_uop
    mov [rsp+36], eax               ; cycle2
    mov eax, [rsp+32]
    test eax, eax
    js  ssm_cnext
    cmp eax, [rsp+36]
    jne ssm_cnext
    ; both uOPs fit in the same cycle
    test r14d, r14d
    jz  ssm_done
    mov ecx, [r12+MOP_UOP1]
    mov edx, eax
    mov r8d, 1
    mov r9, r13
    call ss_uop
    mov ecx, [r12+MOP_UOP2]
    mov edx, eax
    mov r8d, 1
    mov r9, r13
    call ss_uop                     ; returns cycle2 == cycle1
    jmp ssm_done
ssm_cnext:
    inc r15d
    jmp ssm_cloop
ssm_fail:
    mov eax, -1
ssm_done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    ret
ss_mop ENDP

; ===========================================================================
; ss_select_reg (rcx=avail, edx=count, r8=gen) -> eax
;   Port of selectRegister: -1 when empty, RNG only when count > 1.
; ===========================================================================
ss_select_reg PROC
    sub rsp, 40
    mov [rsp+32], rcx                ; avail (8 bytes: 32..39)
    mov [rsp+24], edx                ; count (4 bytes: 24..27, NO overlap)
    test edx, edx
    jle ssr_none
    cmp edx, 1
    je  ssr_one
    mov rcx, r8
    call b2gen_get_u32
    mov ecx, [rsp+24]
    xor edx, edx
    div ecx                         ; edx = eax % count
    mov rcx, [rsp+32]
    mov eax, [rcx+rdx*4]
    jmp ssr_out
ssr_one:
    mov rcx, [rsp+32]
    mov eax, [rcx]
ssr_out:
    add rsp, 40
    ret
ssr_none:
    mov eax, -1
    add rsp, 40
    ret
ss_select_reg ENDP

; ===========================================================================
; ss_sel_src (rcx=instr, edx=cycle, r8=regs, r9=gen) -> eax 0/1
;   Port of SuperscalarInstruction::selectSource.
; ===========================================================================
ss_sel_src PROC
    sub rsp, 88
    mov [rsp+64], rcx                ; instr
    mov [rsp+72], r9                 ; gen
    mov [rsp+80], r8                 ; regs base
    xor r10d, r10d                   ; count
    xor eax, eax                     ; i
    mov r11, [rsp+80]                ; &regs[i]
sss_lp:
    cmp eax, 8
    jge sss_built
    cmp dword ptr [r11], edx
    jg  sss_next                     ; latency > cycle
    mov [rsp+r10*4+32], eax
    inc r10d
sss_next:
    inc eax
    add r11, 16
    jmp sss_lp
sss_built:
    ; if count == 2 && type == IADD_RS && avail contains 5 -> src = 5 (no RNG)
    cmp r10d, 2
    jne sss_reg
    mov rax, [rsp+64]
    mov rax, [rax]
    cmp dword ptr [rax], SS_IADD_RS
    jne sss_reg
    mov eax, [rsp+32]
    cmp eax, 5
    je  sss_r5
    mov eax, [rsp+36]
    cmp eax, 5
    jne sss_reg
sss_r5:
    mov rax, [rsp+64]
    mov dword ptr [rax+CI_SRC], 5
    mov dword ptr [rax+CI_GPAR], 5
    mov eax, 1
    add rsp, 88
    ret
sss_reg:
    lea rcx, [rsp+32]
    mov edx, r10d
    mov r8, [rsp+72]                 ; gen
    call ss_select_reg
    test eax, eax
    js  sss_fail
    mov rcx, [rsp+64]
    mov [rcx+CI_SRC], eax
    cmp dword ptr [rcx+CI_GPISRC], 0
    je  sss_ok
    mov [rcx+CI_GPAR], eax
sss_ok:
    mov eax, 1
    add rsp, 88
    ret
sss_fail:
    xor eax, eax
    add rsp, 88
    ret
ss_sel_src ENDP

; ===========================================================================
; ss_sel_dst (rcx=instr, rdx=(allow<<32)|cycle, r8=regs, r9=gen) -> eax 0/1
;   Port of SuperscalarInstruction::selectDestination.
; ===========================================================================
ss_sel_dst PROC
    sub rsp, 88
    mov [rsp+64], rcx                ; instr
    mov [rsp+72], edx                ; cycle
    shr rdx, 32
    mov [rsp+76], edx                ; allowChainedMul
    xor r10d, r10d                   ; count
    xor eax, eax                     ; i
    mov r11, r8                      ; &regs[i]
ssd_lp:
    cmp eax, 8
    jge ssd_built
    mov ecx, [rsp+72]
    cmp dword ptr [r11], ecx
    jg  ssd_next                     ; latency > cycle
    mov rdx, [rsp+64]                ; instr
    ; (canReuse || i != src)
    cmp dword ptr [rdx+CI_REUSE], 0
    jne ssd_c2ok
    cmp dword ptr [rdx+CI_SRC], eax
    je  ssd_next
ssd_c2ok:
    ; (allow || opGroup != IMUL_R || lastOpGroup != IMUL_R)
    cmp dword ptr [rsp+76], 0
    jne ssd_c3ok
    cmp dword ptr [rdx+CI_GROUP], SS_IMUL_R
    jne ssd_c3ok
    cmp dword ptr [r11+4], SS_IMUL_R
    je  ssd_next
ssd_c3ok:
    ; (lastOpGroup != opGroup || lastOpPar != opGroupPar)
    mov ecx, [r11+4]
    cmp ecx, [rdx+CI_GROUP]
    jne ssd_c4ok
    mov ecx, [r11+8]
    cmp ecx, [rdx+CI_GPAR]
    je  ssd_next
ssd_c4ok:
    ; (type != IADD_RS || i != 5)
    mov rcx, [rdx]
    cmp dword ptr [rcx], SS_IADD_RS
    jne ssd_avail
    cmp eax, 5
    je  ssd_next
ssd_avail:
    mov [rsp+r10*4+32], eax
    inc r10d
ssd_next:
    inc eax
    add r11, 16
    jmp ssd_lp
ssd_built:
    lea rcx, [rsp+32]
    mov edx, r10d
    mov r8, r9
    call ss_select_reg
    test eax, eax
    js  ssd_fail
    mov rcx, [rsp+64]
    mov [rcx+CI_DST], eax
    mov eax, 1
    add rsp, 88
    ret
ssd_fail:
    xor eax, eax
    add rsp, 88
    ret
ss_sel_dst ENDP

; ===========================================================================
; ss_create (rcx=instr, rdx=info, r8=gen)
;   Port of SuperscalarInstruction::create (RNG consumption order matters).
; ===========================================================================
ss_create PROC
    push r12
    push r13
    sub rsp, 40
    mov r12, rcx
    mov r13, r8
    mov [r12+CI_INFO], rdx
    mov dword ptr [r12+CI_SRC], -1
    mov dword ptr [r12+CI_DST], -1
    mov dword ptr [r12+CI_REUSE], 0
    mov dword ptr [r12+CI_GPISRC], 0
    mov eax, [rdx+INFO_TYPE]
    cmp eax, SS_ISUB_R
    je  sc_isub
    cmp eax, SS_IXOR_R
    je  sc_ixor
    cmp eax, SS_IADD_RS
    je  sc_iaddrs
    cmp eax, SS_IMUL_R
    je  sc_imulr
    cmp eax, SS_IROR_C
    je  sc_iror
    cmp eax, SS_IADD_C7
    je  sc_iaddc
    cmp eax, SS_IXOR_C7
    je  sc_ixorc
    cmp eax, SS_IADD_C8
    je  sc_iaddc
    cmp eax, SS_IXOR_C8
    je  sc_ixorc
    cmp eax, SS_IADD_C9
    je  sc_iaddc
    cmp eax, SS_IXOR_C9
    je  sc_ixorc
    cmp eax, SS_IMULH_R
    je  sc_imulh
    cmp eax, SS_ISMULH_R
    je  sc_ismulh
    cmp eax, SS_IMUL_RCP
    je  sc_rcp
    jmp sc_done                     ; NOP / invalid: nothing to set
sc_isub:
    mov dword ptr [r12+CI_MOD], 0
    mov dword ptr [r12+CI_IMM], 0
    mov dword ptr [r12+CI_GROUP], SS_IADD_RS
    mov dword ptr [r12+CI_GPISRC], 1
    jmp sc_done
sc_ixor:
    mov dword ptr [r12+CI_MOD], 0
    mov dword ptr [r12+CI_IMM], 0
    mov dword ptr [r12+CI_GROUP], SS_IXOR_R
    mov dword ptr [r12+CI_GPISRC], 1
    jmp sc_done
sc_iaddrs:
    mov rcx, r13
    call b2gen_get_byte
    mov [r12+CI_MOD], eax
    mov dword ptr [r12+CI_IMM], 0
    mov dword ptr [r12+CI_GROUP], SS_IADD_RS
    mov dword ptr [r12+CI_GPISRC], 1
    jmp sc_done
sc_imulr:
    mov dword ptr [r12+CI_MOD], 0
    mov dword ptr [r12+CI_IMM], 0
    mov dword ptr [r12+CI_GROUP], SS_IMUL_R
    mov dword ptr [r12+CI_GPISRC], 1
    jmp sc_done
sc_iror:
    mov dword ptr [r12+CI_MOD], 0
sc_iror_lp:
    mov rcx, r13
    call b2gen_get_byte
    and eax, 63
    test eax, eax
    jz  sc_iror_lp
    mov [r12+CI_IMM], eax
    mov dword ptr [r12+CI_GROUP], SS_IROR_C
    mov dword ptr [r12+CI_GPAR], -1
    jmp sc_done
sc_iaddc:
    mov dword ptr [r12+CI_MOD], 0
    mov rcx, r13
    call b2gen_get_u32
    mov [r12+CI_IMM], eax
    mov dword ptr [r12+CI_GROUP], SS_IADD_C7
    mov dword ptr [r12+CI_GPAR], -1
    jmp sc_done
sc_ixorc:
    mov dword ptr [r12+CI_MOD], 0
    mov rcx, r13
    call b2gen_get_u32
    mov [r12+CI_IMM], eax
    mov dword ptr [r12+CI_GROUP], SS_IXOR_C7
    mov dword ptr [r12+CI_GPAR], -1
    jmp sc_done
sc_imulh:
    mov dword ptr [r12+CI_REUSE], 1
    mov dword ptr [r12+CI_MOD], 0
    mov dword ptr [r12+CI_IMM], 0
    mov dword ptr [r12+CI_GROUP], SS_IMULH_R
    mov rcx, r13
    call b2gen_get_u32
    mov [r12+CI_GPAR], eax
    jmp sc_done
sc_ismulh:
    mov dword ptr [r12+CI_REUSE], 1
    mov dword ptr [r12+CI_MOD], 0
    mov dword ptr [r12+CI_IMM], 0
    mov dword ptr [r12+CI_GROUP], SS_ISMULH_R
    mov rcx, r13
    call b2gen_get_u32
    mov [r12+CI_GPAR], eax
    jmp sc_done
sc_rcp:
    mov dword ptr [r12+CI_MOD], 0
sc_rcp_lp:
    mov rcx, r13
    call b2gen_get_u32
    mov ecx, eax
    dec ecx
    and ecx, eax                     ; x & (x-1): 0 => zero/power of two
    jz  sc_rcp_lp
    mov [r12+CI_IMM], eax
    mov dword ptr [r12+CI_GROUP], SS_IMUL_RCP
    mov dword ptr [r12+CI_GPAR], -1
sc_done:
    add rsp, 40
    pop r13
    pop r12
    ret
ss_create ENDP

; ===========================================================================
; generateSuperscalar (rcx=prog, rdx=gen)
;   Port of randomx::generateSuperscalar.
; ===========================================================================
generateSuperscalar PROC
    push rbx
    push rbp
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 848

    mov r12, rcx                     ; prog
    mov r13, rdx                     ; gen
    lea r14, [rsp+688]               ; &currentInstruction
    lea r15, [rsp+560]               ; &registers

    ; portBusy[174][3] bytes = 0
    lea rdi, [rsp+32]
    mov ecx, 522
    xor eax, eax
    rep stosb
    ; registers (128 bytes) + currentInstruction (40) + pad = 0
    lea rdi, [rsp+560]
    mov ecx, 176
    xor eax, eax
    rep stosb
    ; scalars (736..847) = 0
    lea rdi, [rsp+736]
    mov ecx, 112
    xor eax, eax
    rep stosb
    ; RegisterInfo: lastOpGroup = -1, lastOpPar = -1 (latency/value = 0)
    mov rax, r15
    mov ecx, 8
gs_reginit:
    mov dword ptr [rax+4], -1
    mov dword ptr [rax+8], -1
    add rax, 16
    dec ecx
    jnz gs_reginit
    ; currentInstruction = Null (info=NOP, src=dst=-1)
    lea rax, info_NOP
    mov [r14+CI_INFO], rax
    mov dword ptr [r14+CI_SRC], -1
    mov dword ptr [r14+CI_DST], -1
    lea rbx, [rsp+32]                ; portBusy base

    jmp gs_cond

gs_body:
    ; ---- select a decode configuration (DecoderBuffer::fetchNext) --------
    mov rax, [r14+CI_INFO]
    mov ecx, [rax+INFO_TYPE]
    cmp ecx, SS_IMULH_R
    je  gs_f3310
    cmp ecx, SS_ISMULH_R
    je  gs_f3310
    mov eax, [rsp+S_MULCNT]          ; mulCount < decodeCycle + 1 ?
    mov edx, [rsp+S_DECYC]
    inc edx
    cmp eax, edx
    jl  gs_f4444
    cmp ecx, SS_IMUL_RCP
    jne gs_fdef
    mov rcx, r13
    call b2gen_get_byte
    test al, 1
    jnz gs_f484
    jmp gs_f493
gs_fdef:
    mov rcx, r13
    call b2gen_get_byte
    and eax, 3
    lea rdx, ss_decode_buffers
    mov rbp, [rdx+rax*8]
    jmp gs_fdone
gs_f3310:
    lea rbp, ss_b3310
    jmp gs_fdone
gs_f4444:
    lea rbp, ss_b4444
    jmp gs_fdone
gs_f484:
    lea rbp, ss_b484
    jmp gs_fdone
gs_f493:
    lea rbp, ss_b493
gs_fdone:
    mov dword ptr [rsp+S_BUFIDX], 0

gs_while:
    mov eax, [rsp+S_BUFIDX]
    cmp eax, [rbp+DB_SIZE]
    jge gs_whiledone
    mov eax, [rsp+S_CYCLE]
    mov [rsp+S_TOPCYC], eax          ; topCycle = cycle

    ; ---- create a new instruction when all macro-ops are issued ---------
    mov ecx, [rsp+S_MOPIDX]
    mov rax, [r14+CI_INFO]
    cmp ecx, [rax+INFO_OPS]
    jl  gs_havemop
    cmp dword ptr [rsp+S_SAT], 0
    jne gs_whiledone
    cmp dword ptr [rsp+S_PROGSZ], 512
    jge gs_whiledone

    ; ---- createForSlot(gen, counts[bufferIndex], index, isLast, isFirst) -
    mov eax, [rsp+S_BUFIDX]
    lea rdx, [rbp+DB_COUNTS]
    mov ecx, [rdx+rax*4]            ; slotSize = counts[bufferIndex]
    mov [rsp+S_SLOTSZ], ecx
    mov eax, [rbp+DB_INDEX]
    mov [rsp+S_FETCHTY], eax
    mov eax, [rsp+S_BUFIDX]
    inc eax
    cmp eax, [rbp+DB_SIZE]
    sete al
    movzx eax, al
    mov [rsp+S_ISLAST], eax

    mov ecx, [rsp+S_SLOTSZ]
    cmp ecx, 3
    je  gs_c3
    cmp ecx, 4
    je  gs_c4
    cmp ecx, 7
    je  gs_c7
    cmp ecx, 8
    je  gs_c8
    cmp ecx, 9
    je  gs_c9
    lea rdx, info_IMUL_RCP          ; slot size 10
    jmp gs_create
gs_c3:
    cmp dword ptr [rsp+S_ISLAST], 0
    je  gs_c3n
    mov rcx, r13
    call b2gen_get_byte
    and eax, 3
    lea rdx, ss_slot3L
    jmp gs_slotsel
gs_c3n:
    mov rcx, r13
    call b2gen_get_byte
    and eax, 1
    lea rdx, ss_slot3
    jmp gs_slotsel
gs_c4:
    cmp dword ptr [rsp+S_FETCHTY], 4
    jne gs_c4n
    cmp dword ptr [rsp+S_ISLAST], 0
    je  gs_c4imul                   ; fetchType==4 && !isLast
gs_c4n:
    mov rcx, r13
    call b2gen_get_byte
    and eax, 1
    lea rdx, ss_slot4
    jmp gs_slotsel
gs_c4imul:
    lea rdx, info_IMUL_R
    jmp gs_create
gs_c7:
    mov rcx, r13
    call b2gen_get_byte
    and eax, 1
    lea rdx, ss_slot7
    jmp gs_slotsel
gs_c8:
    mov rcx, r13
    call b2gen_get_byte
    and eax, 1
    lea rdx, ss_slot8
    jmp gs_slotsel
gs_c9:
    mov rcx, r13
    call b2gen_get_byte
    and eax, 1
    lea rdx, ss_slot9
gs_slotsel:
    mov rdx, [rdx+rax*8]
gs_create:
    mov rcx, r14
    mov r8, r13
    call ss_create
    mov dword ptr [rsp+S_MOPIDX], 0

gs_havemop:
    ; mopPtr = ss_mops[info->mopIdx[macroOpIndex]]
    mov rax, [r14+CI_INFO]
    mov ecx, [rsp+S_MOPIDX]
    mov ecx, [rax+INFO_MOPIDX+rcx*4]
    imul ecx, 20
    lea rax, ss_mops
    add rax, rcx
    mov [rsp+S_MOPPTR], rax

    ; ---- probe: scheduleMop<false>(mop, cycle, depCycle) ---------------
    mov rcx, rax
    mov edx, [rsp+S_CYCLE]
    mov r10d, [rsp+S_DEP]
    shl r10, 32
    or  rdx, r10
    xor r8d, r8d
    mov r9, rbx
    call ss_mop
    test eax, eax
    jns gs_probeok
    mov dword ptr [rsp+S_SAT], 1
    jmp gs_whiledone
gs_probeok:
    mov [rsp+S_SCHED], eax

    ; ---- source register selection (if macroOpIndex == srcOp) ----------
    mov rax, [r14+CI_INFO]
    mov ecx, [rsp+S_MOPIDX]
    cmp ecx, [rax+INFO_SRCOP]
    jne gs_dstsel
    mov dword ptr [rsp+S_FWD], 0
gs_src_lp:
    cmp dword ptr [rsp+S_FWD], 4
    jge gs_throw
    mov rcx, r14
    mov edx, [rsp+S_SCHED]
    mov r8, r15
    mov r9, r13
    call ss_sel_src
    test eax, eax
    jnz gs_dstsel
    inc dword ptr [rsp+S_SCHED]
    inc dword ptr [rsp+S_CYCLE]
    inc dword ptr [rsp+S_FWD]
    jmp gs_src_lp

gs_dstsel:
    ; ---- destination register selection (if macroOpIndex == dstOp) -----
    mov rax, [r14+CI_INFO]
    mov ecx, [rsp+S_MOPIDX]
    cmp ecx, [rax+INFO_DSTOP]
    jne gs_reset
    mov dword ptr [rsp+S_FWD], 0
gs_dst_lp:
    cmp dword ptr [rsp+S_FWD], 4
    jge gs_throw
    mov edx, [rsp+S_SCHED]
    cmp dword ptr [rsp+S_THROW], 0
    setg r10b
    movzx r10d, r10b
    shl r10, 32
    or  rdx, r10
    mov rcx, r14
    mov r8, r15
    mov r9, r13
    call ss_sel_dst
    test eax, eax
    jnz gs_reset
    inc dword ptr [rsp+S_SCHED]
    inc dword ptr [rsp+S_CYCLE]
    inc dword ptr [rsp+S_FWD]
    jmp gs_dst_lp

gs_reset:
    mov dword ptr [rsp+S_THROW], 0

gs_commit:
    ; ---- scheduleMop<true>(mop, sched, sched) --------------------------
    mov rcx, [rsp+S_MOPPTR]
    mov edx, [rsp+S_SCHED]
    mov r10d, edx
    shl r10, 32
    or  rdx, r10
    mov r8d, 1
    mov r9, rbx
    call ss_mop
    test eax, eax
    jns gs_commitok
    mov dword ptr [rsp+S_SAT], 1
    jmp gs_whiledone
gs_commitok:
    mov [rsp+S_SCHED], eax
    ; depCycle = sched + mop.latency
    mov rax, [rsp+S_MOPPTR]
    mov ecx, [rsp+S_SCHED]
    add ecx, [rax+MOP_LAT]
    mov [rsp+S_DEP], ecx
    ; if macroOpIndex == resultOp: retire into registers[dst]
    mov rax, [r14+CI_INFO]
    mov ecx, [rsp+S_MOPIDX]
    cmp ecx, [rax+INFO_RETOP]
    jne gs_noretire
    mov eax, [r14+CI_DST]
    shl rax, 4
    add rax, r15                     ; &registers[dst]
    mov ecx, [rsp+S_DEP]
    mov [rax], ecx                   ; latency
    mov [rsp+S_RETIRE], ecx          ; retireCycle = depCycle
    mov ecx, [r14+CI_GROUP]
    mov [rax+4], ecx                 ; lastOpGroup
    mov ecx, [r14+CI_GPAR]
    mov [rax+8], ecx                 ; lastOpPar
gs_noretire:
    mov rax, [rsp+S_MOPPTR]
    mov ecx, [rax+MOP_SIZE]
    add [rsp+S_CODESZ], ecx
    inc dword ptr [rsp+S_BUFIDX]
    inc dword ptr [rsp+S_MOPIDX]
    inc dword ptr [rsp+S_MOPCNT]
    cmp dword ptr [rsp+S_SCHED], 170
    jl  gs_nosat
    mov dword ptr [rsp+S_SAT], 1
gs_nosat:
    mov eax, [rsp+S_TOPCYC]
    mov [rsp+S_CYCLE], eax
    ; when the instruction is complete, append it to the program
    mov ecx, [rsp+S_MOPIDX]
    mov rax, [r14+CI_INFO]
    cmp ecx, [rax+INFO_OPS]
    jl  gs_while
    mov eax, [rsp+S_PROGSZ]
    lea rdi, [r12+rax*8]
    mov rax, [r14+CI_INFO]
    mov eax, [rax+INFO_TYPE]
    mov byte ptr [rdi], al          ; opcode
    mov eax, [r14+CI_DST]
    mov byte ptr [rdi+1], al        ; dst
    mov eax, [r14+CI_SRC]
    test eax, eax
    jge gs_srccpy
    mov eax, [r14+CI_DST]
gs_srccpy:
    mov byte ptr [rdi+2], al        ; src = src >= 0 ? src : dst
    mov eax, [r14+CI_MOD]
    mov byte ptr [rdi+3], al
    mov eax, [r14+CI_IMM]
    mov [rdi+4], eax
    inc dword ptr [rsp+S_PROGSZ]
    ; mulCount += isMultiplication(type)
    mov rax, [r14+CI_INFO]
    mov ecx, [rax+INFO_TYPE]
    cmp ecx, SS_IMUL_R
    je  gs_ismul
    cmp ecx, SS_IMULH_R
    je  gs_ismul
    cmp ecx, SS_ISMULH_R
    je  gs_ismul
    cmp ecx, SS_IMUL_RCP
    jne gs_while
gs_ismul:
    inc dword ptr [rsp+S_MULCNT]
    jmp gs_while

gs_throw:
    ; source/destination selection failed 4 times
    cmp dword ptr [rsp+S_THROW], 256
    jge gs_abort
    inc dword ptr [rsp+S_THROW]
    mov rax, [r14+CI_INFO]
    mov eax, [rax+INFO_OPS]
    mov [rsp+S_MOPIDX], eax         ; macroOpIndex = info.size
    jmp gs_while
gs_abort:
    lea rax, info_NOP
    mov [r14+CI_INFO], rax
    mov dword ptr [r14+CI_SRC], -1
    mov dword ptr [r14+CI_DST], -1

gs_whiledone:
    inc dword ptr [rsp+S_CYCLE]
    inc dword ptr [rsp+S_DECYC]
gs_cond:
    cmp dword ptr [rsp+S_DECYC], 170
    jge gs_after
    cmp dword ptr [rsp+S_SAT], 0
    jne gs_after
    cmp dword ptr [rsp+S_PROGSZ], 512
    jge gs_after
    jmp gs_body

gs_after:
    ; ---- ASIC latency pass ---------------------------------------------
    lea rdi, [r12+4136]
    mov ecx, 64
    xor eax, eax
    rep stosb
    xor ebx, ebx                    ; i
gs_asic:
    cmp ebx, [rsp+S_PROGSZ]
    jge gs_asicdone
    movzx eax, byte ptr [r12+rbx*8+1]   ; dst
    movzx ecx, byte ptr [r12+rbx*8+2]   ; src
    mov edx, [r12+rax*4+4136]
    inc edx                             ; latDst
    cmp eax, ecx
    je  gs_asicstore
    mov r10d, [r12+rcx*4+4136]
    inc r10d                            ; latSrc
    cmp r10d, edx
    jle gs_asicstore
    mov edx, r10d
gs_asicstore:
    mov [r12+rax*4+4136], edx
    inc ebx
    jmp gs_asic
gs_asicdone:
    xor ebx, ebx                    ; i
    xor r10d, r10d                  ; asicLatencyMax
    xor r11d, r11d                  ; addressReg
gs_addr:
    cmp ebx, 8
    jge gs_addrdone
    mov eax, [r12+rbx*4+4136]
    cmp eax, r10d
    jle gs_addrupd
    mov r10d, eax
    mov r11d, ebx
gs_addrupd:
    mov rax, rbx
    shl rax, 4
    mov eax, [r15+rax]               ; registers[i].latency
    mov [r12+rbx*4+4104], eax        ; cpuLatencies[i]
    inc ebx
    jmp gs_addr
gs_addrdone:
    mov eax, [rsp+S_PROGSZ]
    mov [r12+4096], eax
    mov [r12+4100], r11d
    mov eax, [rsp+S_RETIRE]
    mov [r12+4168], eax
    mov [r12+4172], r10d
    mov eax, [rsp+S_CODESZ]
    mov [r12+4176], eax
    mov eax, [rsp+S_MOPCNT]
    mov [r12+4180], eax
    mov eax, [rsp+S_DECYC]
    mov [r12+4184], eax
    mov eax, [rsp+S_MULCNT]
    mov [r12+4188], eax

    add rsp, 848
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rbp
    pop rbx
    ret
generateSuperscalar ENDP

END
