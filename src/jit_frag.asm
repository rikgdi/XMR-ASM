; XMRASM : RandomX JIT static program fragments (x86-64)
;
; Port of RandomX deps/RandomX/src/jit_compiler_x86_static.asm with all
; asm/*.inc contents inlined.  Byte-for-byte identical instruction/data
; content; used at runtime as memcpy sources for the JIT code buffer.
;
; Scope: V1 + hard AES only.  Fragments for V2/light/soft-AES paths are
; kept so that size anchors (label differences) match the reference.
;
; Exports (PUBLIC):
;   fragment start labels: randomx_program_prologue, randomx_program_loop_load,
;     randomx_program_read_dataset, randomx_prefetch_scratchpad,
;     randomx_program_loop_store, randomx_program_epilogue
;   size table (.const, dd):
;     jit_sz_prologue     = loop_begin - prologue
;     jit_sz_loopload     = program_start - loop_load
;     jit_sz_readdataset  = read_dataset_v2 - read_dataset
;     jit_sz_prefetch     = prefetch_end - prefetch
;     jit_sz_loopstore    = loop_store_hard_aes - loop_store
;     jit_sz_epilogue     = sshash_load - epilogue

option casemap:none

PUBLIC randomx_program_prologue, randomx_program_loop_load
PUBLIC randomx_program_read_dataset, randomx_prefetch_scratchpad
PUBLIC randomx_program_loop_store, randomx_program_epilogue
PUBLIC jit_sz_prologue, jit_sz_loopload, jit_sz_readdataset
PUBLIC jit_sz_prefetch, jit_sz_loopstore, jit_sz_epilogue

; ---------------------------------------------------------------------------
; configuration (inlined from asm/configuration.asm)
; ---------------------------------------------------------------------------
RANDOMX_ARGON_MEMORY EQU 262144t
RANDOMX_ARGON_ITERATIONS EQU 3t
RANDOMX_ARGON_LANES EQU 1t
RANDOMX_ARGON_SALT TEXTEQU <"RandomX\x03">
RANDOMX_CACHE_ACCESSES EQU 8t
RANDOMX_SUPERSCALAR_LATENCY EQU 170t
RANDOMX_DATASET_BASE_SIZE EQU 2147483648t
RANDOMX_DATASET_EXTRA_SIZE EQU 33554368t
RANDOMX_PROGRAM_SIZE_V1 EQU 256t
RANDOMX_PROGRAM_SIZE_V2 EQU 384t
RANDOMX_PROGRAM_MAX_SIZE EQU 384t
RANDOMX_PROGRAM_ITERATIONS EQU 2048t
RANDOMX_PROGRAM_COUNT EQU 8t
RANDOMX_SCRATCHPAD_L3 EQU 2097152t
RANDOMX_SCRATCHPAD_L2 EQU 262144t
RANDOMX_SCRATCHPAD_L1 EQU 16384t
RANDOMX_JUMP_BITS EQU 8t
RANDOMX_JUMP_OFFSET EQU 8t
RANDOMX_FREQ_IADD_RS EQU 16t
RANDOMX_FREQ_IADD_M EQU 7t
RANDOMX_FREQ_ISUB_R EQU 16t
RANDOMX_FREQ_ISUB_M EQU 7t
RANDOMX_FREQ_IMUL_R EQU 16t
RANDOMX_FREQ_IMUL_M EQU 4t
RANDOMX_FREQ_IMULH_R EQU 4t
RANDOMX_FREQ_IMULH_M EQU 1t
RANDOMX_FREQ_ISMULH_R EQU 4t
RANDOMX_FREQ_ISMULH_M EQU 1t
RANDOMX_FREQ_IMUL_RCP EQU 8t
RANDOMX_FREQ_INEG_R EQU 2t
RANDOMX_FREQ_IXOR_R EQU 15t
RANDOMX_FREQ_IXOR_M EQU 5t
RANDOMX_FREQ_IROR_R EQU 8t
RANDOMX_FREQ_IROL_R EQU 2t
RANDOMX_FREQ_ISWAP_R EQU 4t
RANDOMX_FREQ_FSWAP_R EQU 4t
RANDOMX_FREQ_FADD_R EQU 16t
RANDOMX_FREQ_FADD_M EQU 5t
RANDOMX_FREQ_FSUB_R EQU 16t
RANDOMX_FREQ_FSUB_M EQU 5t
RANDOMX_FREQ_FSCAL_R EQU 6t
RANDOMX_FREQ_FMUL_R EQU 32t
RANDOMX_FREQ_FDIV_M EQU 4t
RANDOMX_FREQ_FSQRT_R EQU 6t
RANDOMX_FREQ_CBRANCH EQU 25t
RANDOMX_FREQ_CFROUND EQU 1t
RANDOMX_FREQ_ISTORE EQU 16t
RANDOMX_FREQ_NOP EQU 0t

RANDOMX_SCRATCHPAD_MASK     EQU (RANDOMX_SCRATCHPAD_L3-64)
RANDOMX_DATASET_BASE_MASK   EQU (RANDOMX_DATASET_BASE_SIZE-64)
RANDOMX_CACHE_MASK          EQU (RANDOMX_ARGON_MEMORY*16-1)
RANDOMX_ALIGN               EQU 4096
SUPERSCALAR_OFFSET          EQU ((((RANDOMX_ALIGN + 32 * RANDOMX_PROGRAM_MAX_SIZE) - 1) / (RANDOMX_ALIGN) + 1) * (RANDOMX_ALIGN))
RIP_REL                     EQU 0

; ---------------------------------------------------------------------------
_RRX_JITCODE SEGMENT PAGE READ EXECUTE

; --- randomx_prefetch_scratchpad ------------------------------------------
randomx_prefetch_scratchpad PROC
	mov rdx, rax
	and eax, RANDOMX_SCRATCHPAD_MASK
	prefetcht0 [rsi+rax]
	ror rdx, 32
	and edx, RANDOMX_SCRATCHPAD_MASK
	prefetcht0 [rsi+rdx]
randomx_prefetch_scratchpad ENDP

randomx_prefetch_scratchpad_end PROC
randomx_prefetch_scratchpad_end ENDP

; --- randomx_program_prologue ---------------------------------------------
ALIGN 64
randomx_program_prologue PROC
	;# callee-saved registers - Microsoft x64 calling convention
	sub rsp, 456
	mov qword ptr [rsp+224], rbx
	mov qword ptr [rsp+232], rbp
	mov qword ptr [rsp+240], rsi
	mov qword ptr [rsp+248], rdi
	mov qword ptr [rsp+256], r12
	mov qword ptr [rsp+264], r13
	mov qword ptr [rsp+272], r14
	mov qword ptr [rsp+280], r15
	movdqa xmmword ptr [rsp+288], xmm6
	movdqa xmmword ptr [rsp+304], xmm7
	movdqa xmmword ptr [rsp+320], xmm8
	movdqa xmmword ptr [rsp+336], xmm9
	movdqa xmmword ptr [rsp+352], xmm10
	movdqa xmmword ptr [rsp+368], xmm11
	movdqa xmmword ptr [rsp+384], xmm12
	movdqa xmmword ptr [rsp+400], xmm13
	movdqa xmmword ptr [rsp+416], xmm14
	movdqa xmmword ptr [rsp+432], xmm15

	;# function arguments
	mov qword ptr [rsp+448], rcx  ;# RegisterFile& registerFile
	mov rbp, qword ptr [rdx]      ;# "mx", "ma"
	mov rdi, qword ptr [rdx+8]    ;# uint8_t* dataset
	mov rsi, r8                   ;# uint8_t* scratchpad
	mov rbx, r9                   ;# loop counter

	mov rax, rbp
	mov r8d, ebp
	ror rbp, 32
	mov r9d, ebp

	and r8d, RANDOMX_DATASET_BASE_MASK
	and r9d, RANDOMX_DATASET_BASE_MASK
	prefetchnta byte ptr [rdi+r8]
	prefetchnta byte ptr [rdi+r9]

	;# zero integer registers
	xor r8, r8
	xor r9, r9
	xor r10, r10
	xor r11, r11
	xor r12, r12
	xor r13, r13
	xor r14, r14
	xor r15, r15

	;# load constant registers
	lea rcx, [rcx+120]
	movapd xmm8, xmmword ptr [rcx+72]
	movapd xmm9, xmmword ptr [rcx+88]
	movapd xmm10, xmmword ptr [rcx+104]
	movapd xmm11, xmmword ptr [rcx+120]
	movapd xmm13, xmmword ptr [mantissaMask]
	movapd xmm14, xmmword ptr [exp240]
	movapd xmm15, xmmword ptr [scaleMask]
	mov rdx, rax
	and eax, RANDOMX_SCRATCHPAD_MASK
	ror rdx, 32
	and edx, RANDOMX_SCRATCHPAD_MASK
	jmp rx_program_loop_begin
randomx_program_prologue ENDP

; --- xmm constants (asm/program_xmm_constants.inc) ------------------------
ALIGN 64
mantissaMask:
	db 255, 255, 255, 255, 255, 255, 255, 0, 255, 255, 255, 255, 255, 255, 255, 0
exp240:
	db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
scaleMask:
	db 0, 0, 0, 0, 0, 0, 240, 128, 0, 0, 0, 0, 0, 0, 240, 128

; --- loop begin -----------------------------------------------------------
ALIGN 64
randomx_program_loop_begin PROC
rx_program_loop_begin::
	nop
randomx_program_loop_begin ENDP

; --- randomx_program_loop_load --------------------------------------------
randomx_program_loop_load PROC
	lea rcx, [rsi+rax]
	mov qword ptr [rsp+8], rcx
	xor r8,  qword ptr [rcx+0]
	xor r9,  qword ptr [rcx+8]
	xor r10, qword ptr [rcx+16]
	xor r11, qword ptr [rcx+24]
	xor r12, qword ptr [rcx+32]
	xor r13, qword ptr [rcx+40]
	xor r14, qword ptr [rcx+48]
	xor r15, qword ptr [rcx+56]
	lea rcx, [rsi+rdx]
	mov qword ptr [rsp+16], rcx
	cvtdq2pd xmm0, qword ptr [rcx+0]
	cvtdq2pd xmm1, qword ptr [rcx+8]
	cvtdq2pd xmm2, qword ptr [rcx+16]
	cvtdq2pd xmm3, qword ptr [rcx+24]
	cvtdq2pd xmm4, qword ptr [rcx+32]
	cvtdq2pd xmm5, qword ptr [rcx+40]
	cvtdq2pd xmm6, qword ptr [rcx+48]
	cvtdq2pd xmm7, qword ptr [rcx+56]
	andps xmm4, xmm13
	andps xmm5, xmm13
	andps xmm6, xmm13
	andps xmm7, xmm13
	orps xmm4, xmm14
	orps xmm5, xmm14
	orps xmm6, xmm14
	orps xmm7, xmm14
randomx_program_loop_load ENDP

randomx_program_start PROC
	nop
randomx_program_start ENDP

; --- randomx_program_read_dataset -----------------------------------------
randomx_program_read_dataset PROC
	mov ecx, ebp                       ;# ecx = ma
	and ecx, RANDOMX_DATASET_BASE_MASK
	xor r8, qword ptr [rdi+rcx]
	ror rbp, 32                        ;# swap "ma" and "mx"
	xor rbp, rax                       ;# modify "mx"
	mov edx, ebp                       ;# edx = mx
	and edx, RANDOMX_DATASET_BASE_MASK
	prefetchnta byte ptr [rdi+rdx]
	xor r9,  qword ptr [rdi+rcx+8]
	xor r10, qword ptr [rdi+rcx+16]
	xor r11, qword ptr [rdi+rcx+24]
	xor r12, qword ptr [rdi+rcx+32]
	xor r13, qword ptr [rdi+rcx+40]
	xor r14, qword ptr [rdi+rcx+48]
	xor r15, qword ptr [rdi+rcx+56]
randomx_program_read_dataset ENDP

randomx_program_read_dataset_v2 PROC
	mov ecx, ebp                       ;# ecx = ma
	and ecx, RANDOMX_DATASET_BASE_MASK
	xor r8, qword ptr [rdi+rcx]
	xor rbp, rax                       ;# modify "ma"
	mov edx, ebp                       ;# edx = "ma"
	ror rbp, 32                        ;# swap "ma" and "mx"
	and edx, RANDOMX_DATASET_BASE_MASK
	prefetchnta byte ptr [rdi+rdx]
	xor r9,  qword ptr [rdi+rcx+8]
	xor r10, qword ptr [rdi+rcx+16]
	xor r11, qword ptr [rdi+rcx+24]
	xor r12, qword ptr [rdi+rcx+32]
	xor r13, qword ptr [rdi+rcx+40]
	xor r14, qword ptr [rdi+rcx+48]
	xor r15, qword ptr [rdi+rcx+56]
randomx_program_read_dataset_v2 ENDP

; --- light-mode sshash init/fin (size anchors for V1) ---------------------
randomx_program_read_dataset_sshash_init PROC
	mov qword ptr [rsp+24], r8
	mov qword ptr [rsp+32], r9
	mov qword ptr [rsp+40], r10
	mov qword ptr [rsp+48], r11
	mov qword ptr [rsp+56], r12
	mov qword ptr [rsp+64], r13
	mov qword ptr [rsp+72], r14
	mov qword ptr [rsp+80], r15
	mov qword ptr [rsp+88], rbx
	mov ebx, ebp                       ;# ebx = ma
	shr ebx, 6
	and ebx, RANDOMX_DATASET_BASE_MASK / 64 ;# ebx = Dataset block number
	ror rbp, 32                        ;# swap "ma" and "mx"
	xor rbp, rax                       ;# modify "mx"
	;# add ebx, datasetOffset / 64
	;# call 32768
randomx_program_read_dataset_sshash_init ENDP

randomx_program_read_dataset_sshash_init_v2 PROC
	mov qword ptr [rsp+24], r8
	mov qword ptr [rsp+32], r9
	mov qword ptr [rsp+40], r10
	mov qword ptr [rsp+48], r11
	mov qword ptr [rsp+56], r12
	mov qword ptr [rsp+64], r13
	mov qword ptr [rsp+72], r14
	mov qword ptr [rsp+80], r15
	mov qword ptr [rsp+88], rbx
	mov ebx, ebp                       ;# ebx = ma
	shr ebx, 6
	and ebx, RANDOMX_DATASET_BASE_MASK / 64 ;# ebx = Dataset block number
	xor rbp, rax                       ;# modify "mx"
	ror rbp, 32                        ;# swap "ma" and "mx"
	;# add ebx, datasetOffset / 64
	;# call 32768
randomx_program_read_dataset_sshash_init_v2 ENDP

randomx_program_read_dataset_sshash_fin PROC
	xor r8, qword ptr [rsp+24]
	xor r9, qword ptr [rsp+32]
	xor r10, qword ptr [rsp+40]
	xor r11, qword ptr [rsp+48]
	xor r12, qword ptr [rsp+56]
	xor r13, qword ptr [rsp+64]
	xor r14, qword ptr [rsp+72]
	xor r15, qword ptr [rsp+80]
	mov rbx, qword ptr [rsp+88]
randomx_program_read_dataset_sshash_fin ENDP

; --- randomx_program_loop_store (V1) --------------------------------------
randomx_program_loop_store PROC
	mov rcx, qword ptr [rsp+16]
	mov qword ptr [rcx+0], r8
	mov qword ptr [rcx+8], r9
	mov qword ptr [rcx+16], r10
	mov qword ptr [rcx+24], r11
	mov qword ptr [rcx+32], r12
	mov qword ptr [rcx+40], r13
	mov qword ptr [rcx+48], r14
	mov qword ptr [rcx+56], r15
	mov rcx, qword ptr [rsp+8]
	xorpd xmm0, xmm4
	xorpd xmm1, xmm5
	xorpd xmm2, xmm6
	xorpd xmm3, xmm7
	movapd xmmword ptr [rcx+0], xmm0
	movapd xmmword ptr [rcx+16], xmm1
	movapd xmmword ptr [rcx+32], xmm2
	movapd xmmword ptr [rcx+48], xmm3
randomx_program_loop_store ENDP

; --- V2 store fragments (size anchors) ------------------------------------
randomx_program_loop_store_hard_aes PROC
	mov rcx, qword ptr [rsp+16]
	mov qword ptr [rcx+0], r8
	mov qword ptr [rcx+8], r9
	mov qword ptr [rcx+16], r10
	mov qword ptr [rcx+24], r11
	mov qword ptr [rcx+32], r12
	mov qword ptr [rcx+40], r13
	mov qword ptr [rcx+48], r14
	mov qword ptr [rcx+56], r15
	mov rcx, qword ptr [rsp+8]
	aesenc xmm0, xmm4
	aesdec xmm1, xmm4
	aesenc xmm2, xmm4
	aesdec xmm3, xmm4
	aesenc xmm0, xmm5
	aesdec xmm1, xmm5
	aesenc xmm2, xmm5
	aesdec xmm3, xmm5
	aesenc xmm0, xmm6
	aesdec xmm1, xmm6
	aesenc xmm2, xmm6
	aesdec xmm3, xmm6
	aesenc xmm0, xmm7
	aesdec xmm1, xmm7
	aesenc xmm2, xmm7
	aesdec xmm3, xmm7
	movapd xmmword ptr [rcx+0], xmm0
	movapd xmmword ptr [rcx+16], xmm1
	movapd xmmword ptr [rcx+32], xmm2
	movapd xmmword ptr [rcx+48], xmm3
randomx_program_loop_store_hard_aes ENDP

randomx_program_loop_store_soft_aes PROC
	mov rcx, qword ptr [rsp+16]
	mov qword ptr [rcx+0], r8
	mov qword ptr [rcx+8], r9
	mov qword ptr [rcx+16], r10
	mov qword ptr [rcx+24], r11
	mov qword ptr [rcx+32], r12
	mov qword ptr [rcx+40], r13
	mov qword ptr [rcx+48], r14
	mov qword ptr [rcx+56], r15
	mov rcx, qword ptr [rsp+8]

	movapd xmmword ptr [rsp+96], xmm0
	movapd xmmword ptr [rsp+112], xmm1
	movapd xmmword ptr [rsp+128], xmm2
	movapd xmmword ptr [rsp+144], xmm3
	movapd xmmword ptr [rsp+160], xmm4
	movapd xmmword ptr [rsp+176], xmm5
	movapd xmmword ptr [rsp+192], xmm6
	movapd xmmword ptr [rsp+208], xmm7

	mov qword ptr [rsp+24], rax
	mov qword ptr [rsp+40], rcx
	mov qword ptr [rsp+48], rdx
	mov qword ptr [rsp+56], rbp
	mov qword ptr [rsp+72], rsi
	mov qword ptr [rsp+80], rdi
	mov qword ptr [rsp+88], rbx

	lea rsi, [rsp+160]
	lea rdi, [rsp+96]
	call soft_aes_enc
	lea rsi, [rsp+160]
	lea rdi, [rsp+112]
	call soft_aes_dec
	lea rsi, [rsp+160]
	lea rdi, [rsp+128]
	call soft_aes_enc
	lea rsi, [rsp+160]
	lea rdi, [rsp+144]
	call soft_aes_dec

	lea rsi, [rsp+176]
	lea rdi, [rsp+96]
	call soft_aes_enc
	lea rsi, [rsp+176]
	lea rdi, [rsp+112]
	call soft_aes_dec
	lea rsi, [rsp+176]
	lea rdi, [rsp+128]
	call soft_aes_enc
	lea rsi, [rsp+176]
	lea rdi, [rsp+144]
	call soft_aes_dec

	lea rsi, [rsp+192]
	lea rdi, [rsp+96]
	call soft_aes_enc
	lea rsi, [rsp+192]
	lea rdi, [rsp+112]
	call soft_aes_dec
	lea rsi, [rsp+192]
	lea rdi, [rsp+128]
	call soft_aes_enc
	lea rsi, [rsp+192]
	lea rdi, [rsp+144]
	call soft_aes_dec

	lea rsi, [rsp+208]
	lea rdi, [rsp+96]
	call soft_aes_enc
	lea rsi, [rsp+208]
	lea rdi, [rsp+112]
	call soft_aes_dec
	lea rsi, [rsp+208]
	lea rdi, [rsp+128]
	call soft_aes_enc
	lea rsi, [rsp+208]
	lea rdi, [rsp+144]
	call soft_aes_dec

	mov rax, qword ptr [rsp+24]
	mov rcx, qword ptr [rsp+40]
	mov rdx, qword ptr [rsp+48]
	mov rbp, qword ptr [rsp+56]
	mov rsi, qword ptr [rsp+72]
	mov rdi, qword ptr [rsp+80]
	mov rbx, qword ptr [rsp+88]

	movapd xmm0, xmmword ptr [rsp+96]
	movapd xmm1, xmmword ptr [rsp+112]
	movapd xmm2, xmmword ptr [rsp+128]
	movapd xmm3, xmmword ptr [rsp+144]

	movapd xmmword ptr [rcx+0], xmm0
	movapd xmmword ptr [rcx+16], xmm1
	movapd xmmword ptr [rcx+32], xmm2
	movapd xmmword ptr [rcx+48], xmm3
randomx_program_loop_store_soft_aes ENDP

; --- randomx_program_loop_end (size anchor only) --------------------------
randomx_program_loop_end PROC
	sub ebx, 1
	jnz rx_program_end
	jmp rx_program_end
randomx_program_loop_end ENDP

; --- soft AES (V2 soft path; kept for layout fidelity) --------------------
randomx_program_soft_aes PROC
soft_aes_enc::
	mov eax, dword ptr [rsi+0]
	mov ebx, dword ptr [rsi+4]
	mov ecx, dword ptr [rsi+8]
	mov edx, dword ptr [rsi+12]

	mov rsi, qword ptr [aes_lut_enc+RIP_REL]

	movzx ebp, byte ptr [rdi+0]
	xor eax, dword ptr [rsi+rbp*4]
	movzx ebp, byte ptr [rdi+1]
	xor edx, dword ptr [rsi+rbp*4+1024]
	movzx ebp, byte ptr [rdi+2]
	xor ecx, dword ptr [rsi+rbp*4+2048]
	movzx ebp, byte ptr [rdi+3]
	xor ebx, dword ptr [rsi+rbp*4+3072]

	movzx ebp, byte ptr [rdi+4]
	xor ebx, dword ptr [rsi+rbp*4]
	movzx ebp, byte ptr [rdi+5]
	xor eax, dword ptr [rsi+rbp*4+1024]
	movzx ebp, byte ptr [rdi+6]
	xor edx, dword ptr [rsi+rbp*4+2048]
	movzx ebp, byte ptr [rdi+7]
	xor ecx, dword ptr [rsi+rbp*4+3072]

	movzx ebp, byte ptr [rdi+8]
	xor ecx, dword ptr [rsi+rbp*4]
	movzx ebp, byte ptr [rdi+9]
	xor ebx, dword ptr [rsi+rbp*4+1024]
	movzx ebp, byte ptr [rdi+10]
	xor eax, dword ptr [rsi+rbp*4+2048]
	movzx ebp, byte ptr [rdi+11]
	xor edx, dword ptr [rsi+rbp*4+3072]

	movzx ebp, byte ptr [rdi+12]
	xor edx, dword ptr [rsi+rbp*4]
	movzx ebp, byte ptr [rdi+13]
	xor ecx, dword ptr [rsi+rbp*4+1024]
	movzx ebp, byte ptr [rdi+14]
	xor ebx, dword ptr [rsi+rbp*4+2048]
	movzx ebp, byte ptr [rdi+15]
	xor eax, dword ptr [rsi+rbp*4+3072]

	mov dword ptr [rdi+0], eax
	mov dword ptr [rdi+4], ebx
	mov dword ptr [rdi+8], ecx
	mov dword ptr [rdi+12], edx

	ret
soft_aes_dec::
	mov eax, dword ptr [rsi+0]
	mov ebx, dword ptr [rsi+4]
	mov ecx, dword ptr [rsi+8]
	mov edx, dword ptr [rsi+12]

	mov rsi, qword ptr [aes_lut_dec+RIP_REL]

	movzx ebp, byte ptr [rdi+0]
	xor eax, dword ptr [rsi+rbp*4]
	movzx ebp, byte ptr [rdi+1]
	xor ebx, dword ptr [rsi+rbp*4+1024]
	movzx ebp, byte ptr [rdi+2]
	xor ecx, dword ptr [rsi+rbp*4+2048]
	movzx ebp, byte ptr [rdi+3]
	xor edx, dword ptr [rsi+rbp*4+3072]

	movzx ebp, byte ptr [rdi+4]
	xor ebx, dword ptr [rsi+rbp*4]
	movzx ebp, byte ptr [rdi+5]
	xor ecx, dword ptr [rsi+rbp*4+1024]
	movzx ebp, byte ptr [rdi+6]
	xor edx, dword ptr [rsi+rbp*4+2048]
	movzx ebp, byte ptr [rdi+7]
	xor eax, dword ptr [rsi+rbp*4+3072]

	movzx ebp, byte ptr [rdi+8]
	xor ecx, dword ptr [rsi+rbp*4]
	movzx ebp, byte ptr [rdi+9]
	xor edx, dword ptr [rsi+rbp*4+1024]
	movzx ebp, byte ptr [rdi+10]
	xor eax, dword ptr [rsi+rbp*4+2048]
	movzx ebp, byte ptr [rdi+11]
	xor ebx, dword ptr [rsi+rbp*4+3072]

	movzx ebp, byte ptr [rdi+12]
	xor edx, dword ptr [rsi+rbp*4]
	movzx ebp, byte ptr [rdi+13]
	xor eax, dword ptr [rsi+rbp*4+1024]
	movzx ebp, byte ptr [rdi+14]
	xor ebx, dword ptr [rsi+rbp*4+2048]
	movzx ebp, byte ptr [rdi+15]
	xor ecx, dword ptr [rsi+rbp*4+3072]

	mov dword ptr [rdi+0], eax
	mov dword ptr [rdi+4], ebx
	mov dword ptr [rdi+8], ecx
	mov dword ptr [rdi+12], edx

	ret
randomx_program_soft_aes ENDP

randomx_program_soft_aes_end PROC
aes_lut_enc::
	db 0, 0, 0, 0, 0, 0, 0, 0
aes_lut_dec::
	db 0, 0, 0, 0, 0, 0, 0, 0
randomx_program_soft_aes_end ENDP

; --- randomx_dataset_init (JIT dataset init; not used by the miner yet) ---
ALIGN 64
randomx_dataset_init PROC
	push rbx
	push rbp
	push rdi
	push rsi
	push r12
	push r13
	push r14
	push r15
	mov rdi, qword ptr [rcx] ;# cache->memory
	mov rsi, rdx ;# dataset
	mov rbp, r8  ;# block index
	push r9      ;# max. block index
init_block_loop:
	prefetchw byte ptr [rsi]
	mov rbx, rbp
	db 232 ;# 0xE8 = call
	dd SUPERSCALAR_OFFSET - distance
	distance equ $ - offset randomx_dataset_init
	mov qword ptr [rsi+0], r8
	mov qword ptr [rsi+8], r9
	mov qword ptr [rsi+16], r10
	mov qword ptr [rsi+24], r11
	mov qword ptr [rsi+32], r12
	mov qword ptr [rsi+40], r13
	mov qword ptr [rsi+48], r14
	mov qword ptr [rsi+56], r15
	add rbp, 1
	add rsi, 64
	cmp rbp, qword ptr [rsp]
	jb init_block_loop
	pop r9
	pop r15
	pop r14
	pop r13
	pop r12
	pop rsi
	pop rdi
	pop rbp
	pop rbx
	ret
randomx_dataset_init ENDP

; --- randomx_program_epilogue ---------------------------------------------
ALIGN 64
randomx_program_epilogue PROC
	;# save VM register values
	mov rcx, qword ptr [rsp+448]
	mov qword ptr [rcx+0], r8
	mov qword ptr [rcx+8], r9
	mov qword ptr [rcx+16], r10
	mov qword ptr [rcx+24], r11
	mov qword ptr [rcx+32], r12
	mov qword ptr [rcx+40], r13
	mov qword ptr [rcx+48], r14
	mov qword ptr [rcx+56], r15
	movdqa xmmword ptr [rcx+64], xmm0
	movdqa xmmword ptr [rcx+80], xmm1
	movdqa xmmword ptr [rcx+96], xmm2
	movdqa xmmword ptr [rcx+112], xmm3
	lea rcx, [rcx+64]
	movdqa xmmword ptr [rcx+64], xmm4
	movdqa xmmword ptr [rcx+80], xmm5
	movdqa xmmword ptr [rcx+96], xmm6
	movdqa xmmword ptr [rcx+112], xmm7
	;# restore callee-saved registers - Microsoft x64 calling convention
	movdqa xmm15, xmmword ptr [rsp+432]
	movdqa xmm14, xmmword ptr [rsp+416]
	movdqa xmm13, xmmword ptr [rsp+400]
	movdqa xmm12, xmmword ptr [rsp+384]
	movdqa xmm11, xmmword ptr [rsp+368]
	movdqa xmm10, xmmword ptr [rsp+352]
	movdqa xmm9, xmmword ptr [rsp+336]
	movdqa xmm8, xmmword ptr [rsp+320]
	movdqa xmm7, xmmword ptr [rsp+304]
	movdqa xmm6, xmmword ptr [rsp+288]
	mov r15, qword ptr [rsp+280]
	mov r14, qword ptr [rsp+272]
	mov r13, qword ptr [rsp+264]
	mov r12, qword ptr [rsp+256]
	mov rdi, qword ptr [rsp+248]
	mov rsi, qword ptr [rsp+240]
	mov rbp, qword ptr [rsp+232]
	mov rbx, qword ptr [rsp+224]

	add rsp, 456

	;# program finished
	ret
randomx_program_epilogue ENDP

; --- light-mode sshash fragments (anchors) --------------------------------
ALIGN 64
randomx_sshash_load PROC
	xor r8, qword ptr [rbx+0]
	xor r9, qword ptr [rbx+8]
	xor r10, qword ptr [rbx+16]
	xor r11, qword ptr [rbx+24]
	xor r12, qword ptr [rbx+32]
	xor r13, qword ptr [rbx+40]
	xor r14, qword ptr [rbx+48]
	xor r15, qword ptr [rbx+56]
randomx_sshash_load ENDP

randomx_sshash_prefetch PROC
	and rbx, RANDOMX_CACHE_MASK
	shl rbx, 6
	add rbx, rdi
	prefetchnta byte ptr [rbx]
randomx_sshash_prefetch ENDP

randomx_sshash_end PROC
	nop
randomx_sshash_end ENDP

ALIGN 64
randomx_sshash_init PROC
	lea r8, [rbx+1]
	and rbx, RANDOMX_CACHE_MASK
	shl rbx, 6
	add rbx, rdi
	prefetchnta byte ptr [rbx]
	imul r8, qword ptr [r0_mul]
	mov r9, qword ptr [r1_add]
	xor r9, r8
	mov r10, qword ptr [r2_add]
	xor r10, r8
	mov r11, qword ptr [r3_add]
	xor r11, r8
	mov r12, qword ptr [r4_add]
	xor r12, r8
	mov r13, qword ptr [r5_add]
	xor r13, r8
	mov r14, qword ptr [r6_add]
	xor r14, r8
	mov r15, qword ptr [r7_add]
	xor r15, r8
	jmp rx_program_end
randomx_sshash_init ENDP

; --- sshash constants (asm/program_sshash_constants.inc) ------------------
ALIGN 64
r0_mul:
	;#/ 6364136223846793005
	db 45, 127, 149, 76, 45, 244, 81, 88
r1_add:
	;#/ 9298411001130361340
	db 252, 161, 245, 89, 138, 151, 10, 129
r2_add:
	;#/ 12065312585734608966
	db 70, 216, 194, 56, 223, 153, 112, 167
r3_add:
	;#/ 9306329213124626780
	db 92, 73, 34, 191, 28, 185, 38, 129
r4_add:
	;#/ 5281919268842080866
	db 98, 138, 159, 23, 151, 37, 77, 73
r5_add:
	;#/ 10536153434571861004
	db 12, 236, 170, 206, 185, 239, 55, 146
r6_add:
	;#/ 3398623926847679864
	db 120, 45, 230, 108, 116, 86, 42, 47
r7_add:
	;#/ 9549104520008361294
	db 78, 229, 44, 182, 247, 59, 133, 132

ALIGN 64
randomx_program_end PROC
rx_program_end::
	nop
randomx_program_end ENDP

ALIGN 64
randomx_reciprocal_fast PROC
	mov edx, 1
	mov r8, rcx
	xor eax, eax
	bsr rcx, rcx
	shl rdx, cl
	div r8
	ret
randomx_reciprocal_fast ENDP

_RRX_JITCODE ENDS

; ---------------------------------------------------------------------------
; size table (label differences, evaluated within this module)
; ---------------------------------------------------------------------------
.const
jit_sz_prologue     dd randomx_program_loop_begin - randomx_program_prologue
jit_sz_loopload     dd randomx_program_start - randomx_program_loop_load
jit_sz_readdataset  dd randomx_program_read_dataset_v2 - randomx_program_read_dataset
jit_sz_prefetch     dd randomx_prefetch_scratchpad_end - randomx_prefetch_scratchpad
jit_sz_loopstore    dd randomx_program_loop_store_hard_aes - randomx_program_loop_store
jit_sz_epilogue     dd randomx_sshash_load - randomx_program_epilogue

END
