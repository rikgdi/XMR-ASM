; ============================================================================
; vm.asm - RandomX virtual machine flow (V1, JIT + FULL_MEM)
;
;   randomx_create_vm(flags, cache, dataset) -> vm | 0
;   randomx_destroy_vm(vm)
;   randomx_vm_set_dataset(vm, dataset)
;   randomx_calculate_hash(vm, input, size, output)
;   randomx_calculate_hash_first(vm, input, size)
;   randomx_calculate_hash_next(vm, nextInput, size, output)
;   randomx_calculate_hash_last(vm, output)
;
; Machine block (single mem_alloc, zero-filled):
;   +0    q  jit state            +8    q  dataset memory base
;   +16   q  scratchpad ptr       +24   q  program func (code ptr)
;   +32   d  vm flags             +48   tempHash[64]
;   +112  ProgramConfiguration 32 (+16 readReg0..3)
;   +144  MemoryRegisters {mx:4, ma:4, memory:8}  (+152 memory)
;   +168  q  datasetOffset
;   +192  Program 3200 (entropyBuffer[16] then instructions)
;   +3456 RegisterFile 256 {r[8], f[4], e[4], a[4]}
;   +3776 scratchpad 2097152        size 2100928
; ============================================================================
option casemap:none

PUBLIC randomx_create_vm, randomx_destroy_vm, randomx_vm_set_dataset
PUBLIC randomx_calculate_hash, randomx_calculate_hash_first
PUBLIC randomx_calculate_hash_next, randomx_calculate_hash_last
PUBLIC vx_run

EXTERNDEF blake2b:PROC
EXTERNDEF fillAes1Rx4:PROC
EXTERNDEF fillAes4Rx4:PROC
EXTERNDEF hashAes1Rx4:PROC
EXTERNDEF hashAndFillAes1Rx4:PROC
EXTERNDEF mem_alloc:PROC
EXTERNDEF mem_free:PROC
EXTERNDEF jit_create:PROC
EXTERNDEF jit_destroy:PROC
EXTERNDEF jit_set_flags:PROC
EXTERNDEF jit_get_code:PROC
EXTERNDEF jit_generate_program:PROC

VX_JIT        EQU 0
VX_DS         EQU 8
VX_SP         EQU 16
VX_CODE       EQU 24
VX_FLAGS      EQU 32
VX_TMEM       EQU 48
VX_CONFIG     EQU 112
VX_MEM        EQU 144
VX_DOFF       EQU 168
VX_PROG       EQU 192
VX_REG        EQU 3456
VX_REGA       EQU 3648
VX_SPDATA     EQU 3776
VX_SIZE       EQU 2100928
SCRATCHPAD_SZ EQU 2097152
PROG_SZ       EQU 3200
REGFILE_SZ    EQU 256
MXCSR_DEF     EQU 9FC0h

; rax = small positive double bits from entropy
SMALLBITS MACRO
    mov rdx, rax
    shr rdx, 59
    add rdx, 1023
    and rdx, 7FFh
    shl rdx, 52
    mov rcx, 000FFFFFFFFFFFFFh
    and rax, rcx
    or  rax, rdx
ENDM

; rax = float mask from entropy (static exponent + 22 low bits)
FLOATMASK MACRO
    mov rdx, rax
    shr rdx, 60
    shl rdx, 4
    or  rdx, 300h
    shl rdx, 52
    mov rcx, 3FFFFFh
    and rax, rcx
    or  rax, rdx
ENDM

.code

; ---------------------------------------------------------------------------
; randomx_create_vm (rcx=flags, rdx=cache, r8=dataset) -> rax = vm | 0
; ---------------------------------------------------------------------------
randomx_create_vm PROC
    push rbx
    push r12
    push r13
    sub  rsp, 32
    mov  r12d, ecx                    ; flags
    mov  r13, r8                      ; dataset struct ptr
    mov  rcx, VX_SIZE
    call mem_alloc
    test rax, rax
    jz   cvm_fail
    mov  rbx, rax
    mov  dword ptr [rbx+VX_FLAGS], r12d
    lea  rax, [rbx+VX_SPDATA]
    mov  [rbx+VX_SP], rax
    test r13, r13
    jz   cvm_jit
    mov  rax, [r13]
    mov  [rbx+VX_DS], rax
cvm_jit:
    call jit_create
    test rax, rax
    jz   cvm_free
    mov  [rbx+VX_JIT], rax
    mov  rcx, rax
    mov  edx, r12d
    call jit_set_flags
    mov  rcx, [rbx+VX_JIT]
    call jit_get_code
    mov  [rbx+VX_CODE], rax
    mov  rax, rbx
    jmp  cvm_done
cvm_free:
    mov  rcx, rbx
    call mem_free
cvm_fail:
    xor  eax, eax
cvm_done:
    add  rsp, 32
    pop  r13
    pop  r12
    pop  rbx
    ret
randomx_create_vm ENDP

; ---------------------------------------------------------------------------
; randomx_destroy_vm (rcx=vm)
; ---------------------------------------------------------------------------
randomx_destroy_vm PROC
    test rcx, rcx
    jz   dvm_ret
    push rbx
    sub  rsp, 32
    mov  rbx, rcx
    mov  rcx, [rbx+VX_JIT]
    test rcx, rcx
    jz   dvm_free
    call jit_destroy
dvm_free:
    mov  rcx, rbx
    call mem_free
    add  rsp, 32
    pop  rbx
dvm_ret:
    ret
randomx_destroy_vm ENDP

; ---------------------------------------------------------------------------
; randomx_vm_set_dataset (rcx=vm, rdx=dataset struct | 0)
; ---------------------------------------------------------------------------
randomx_vm_set_dataset PROC
    test rdx, rdx
    jz   svd_zero
    mov  rax, [rdx]
    mov  [rcx+VX_DS], rax
    ret
svd_zero:
    mov  qword ptr [rcx+VX_DS], 0
    ret
randomx_vm_set_dataset ENDP

; ---------------------------------------------------------------------------
; vx_run (rcx=vm, rdx=seed): generateProgram + initialize + JIT generate
;   + execute.  Returns via tail-jump into the program function.
; ---------------------------------------------------------------------------
vx_run PROC
    push rbx
    push rsi
    push rdi
    sub  rsp, 32
    mov  rbx, rcx
    mov  rsi, rdx                      ; seed = tempHash ptr
    mov  rcx, rsi
    mov  edx, PROG_SZ
    lea  r8, [rbx+VX_PROG]
    call fillAes4Rx4
    lea  rdi, [rbx+VX_PROG]            ; entropy buffer
    ; reg.a[i] = smallPositiveFloatBits(entropy[2i, 2i+1])
    mov  rax, [rdi+0]
    SMALLBITS
    mov  [rbx+VX_REGA+0], rax
    mov  rax, [rdi+8]
    SMALLBITS
    mov  [rbx+VX_REGA+8], rax
    mov  rax, [rdi+16]
    SMALLBITS
    mov  [rbx+VX_REGA+16], rax
    mov  rax, [rdi+24]
    SMALLBITS
    mov  [rbx+VX_REGA+24], rax
    mov  rax, [rdi+32]
    SMALLBITS
    mov  [rbx+VX_REGA+32], rax
    mov  rax, [rdi+40]
    SMALLBITS
    mov  [rbx+VX_REGA+40], rax
    mov  rax, [rdi+48]
    SMALLBITS
    mov  [rbx+VX_REGA+48], rax
    mov  rax, [rdi+56]
    SMALLBITS
    mov  [rbx+VX_REGA+56], rax
    ; mem.ma = entropy8 & ~63 (2GB-1 aligned), mem.mx = entropy10
    mov  rax, [rdi+64]
    and  eax, 7FFFFFC0h
    mov  [rbx+VX_MEM+4], eax
    mov  eax, dword ptr [rdi+80]
    mov  [rbx+VX_MEM], eax
    ; readReg0..3 from entropy12 bit pairs
    mov  rax, [rdi+96]
    mov  edx, eax
    and  edx, 1
    mov  [rbx+VX_CONFIG+16], edx
    shr  rax, 1
    mov  edx, eax
    and  edx, 1
    add  edx, 2
    mov  [rbx+VX_CONFIG+20], edx
    shr  rax, 1
    mov  edx, eax
    and  edx, 1
    add  edx, 4
    mov  [rbx+VX_CONFIG+24], edx
    shr  rax, 1
    and  eax, 1
    add  eax, 6
    mov  [rbx+VX_CONFIG+28], eax
    ; datasetOffset = (entropy13 % 524288) * 64
    mov  rax, [rdi+104]
    and  eax, 7FFFFh
    shl  rax, 6
    mov  [rbx+VX_DOFF], rax
    ; config.eMask = floatMask(entropy14, 15)
    mov  rax, [rdi+112]
    FLOATMASK
    mov  [rbx+VX_CONFIG], rax
    mov  rax, [rdi+120]
    FLOATMASK
    mov  [rbx+VX_CONFIG+8], rax
    ; JIT: generate program code
    mov  rcx, [rbx+VX_JIT]
    lea  rdx, [rbx+VX_PROG]
    lea  r8, [rbx+VX_CONFIG]
    call jit_generate_program
    ; mem.memory = dataset + datasetOffset
    mov  rax, [rbx+VX_DS]
    add  rax, [rbx+VX_DOFF]
    mov  [rbx+VX_MEM+8], rax
    ; execute: ProgramFunc(reg, mem, scratchpad, iterations)
    lea  rcx, [rbx+VX_REG]
    lea  rdx, [rbx+VX_MEM]
    mov  r8, [rbx+VX_SP]
    mov  r9d, 2048
    mov  rax, [rbx+VX_CODE]
    add  rsp, 32
    pop  rdi
    pop  rsi
    pop  rbx
    jmp  rax
vx_run ENDP

; ---------------------------------------------------------------------------
; randomx_calculate_hash_first (rcx=vm, rdx=input, r8=size)
; ---------------------------------------------------------------------------
randomx_calculate_hash_first PROC
    push rbx
    push rsi
    push rdi
    sub  rsp, 32
    mov  rbx, rcx
    mov  rsi, rdx
    mov  rdi, r8
    lea  rcx, [rbx+VX_TMEM]
    mov  edx, 64
    mov  r8, rsi
    mov  r9, rdi
    call blake2b
    lea  rcx, [rbx+VX_TMEM]
    mov  rdx, SCRATCHPAD_SZ
    mov  r8, [rbx+VX_SP]
    call fillAes1Rx4
    add  rsp, 32
    pop  rdi
    pop  rsi
    pop  rbx
    ret
randomx_calculate_hash_first ENDP

; ---------------------------------------------------------------------------
; randomx_calculate_hash (rcx=vm, rdx=input, r8=size, r9=output)
; ---------------------------------------------------------------------------
randomx_calculate_hash PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub  rsp, 48
    mov  rbx, rcx
    mov  rsi, rdx
    mov  rdi, r8
    mov  r12, r9
    stmxcsr dword ptr [rsp+40]
    lea  rcx, [rbx+VX_TMEM]
    mov  edx, 64
    mov  r8, rsi
    mov  r9, rdi
    call blake2b
    lea  rcx, [rbx+VX_TMEM]
    mov  rdx, SCRATCHPAD_SZ
    mov  r8, [rbx+VX_SP]
    call fillAes1Rx4
    mov  dword ptr [rsp+44], MXCSR_DEF
    ldmxcsr dword ptr [rsp+44]
    mov  r13d, 7
vhc_loop:
    mov  rcx, rbx
    lea  rdx, [rbx+VX_TMEM]
    call vx_run
    lea  rcx, [rbx+VX_TMEM]
    mov  edx, 64
    lea  r8, [rbx+VX_REG]
    mov  r9d, REGFILE_SZ
    call blake2b
    dec  r13d
    jnz  vhc_loop
    mov  rcx, rbx
    lea  rdx, [rbx+VX_TMEM]
    call vx_run
    mov  rcx, [rbx+VX_SP]
    mov  rdx, SCRATCHPAD_SZ
    lea  r8, [rbx+VX_REGA]
    call hashAes1Rx4
    mov  rcx, r12
    mov  edx, 32
    lea  r8, [rbx+VX_REG]
    mov  r9d, REGFILE_SZ
    call blake2b
    ldmxcsr dword ptr [rsp+40]
    add  rsp, 48
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
randomx_calculate_hash ENDP

; ---------------------------------------------------------------------------
; randomx_calculate_hash_next (rcx=vm, rdx=nextInput, r8=size, r9=output)
; ---------------------------------------------------------------------------
randomx_calculate_hash_next PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub  rsp, 48
    mov  rbx, rcx
    mov  rsi, rdx
    mov  rdi, r8
    mov  r12, r9
    mov  dword ptr [rsp+44], MXCSR_DEF
    ldmxcsr dword ptr [rsp+44]
    mov  r13d, 7
vhn_loop:
    mov  rcx, rbx
    lea  rdx, [rbx+VX_TMEM]
    call vx_run
    lea  rcx, [rbx+VX_TMEM]
    mov  edx, 64
    lea  r8, [rbx+VX_REG]
    mov  r9d, REGFILE_SZ
    call blake2b
    dec  r13d
    jnz  vhn_loop
    mov  rcx, rbx
    lea  rdx, [rbx+VX_TMEM]
    call vx_run
    lea  rcx, [rbx+VX_TMEM]
    mov  edx, 64
    mov  r8, rsi
    mov  r9, rdi
    call blake2b
    mov  rcx, [rbx+VX_SP]
    mov  rdx, SCRATCHPAD_SZ
    lea  r8, [rbx+VX_REGA]
    lea  r9, [rbx+VX_TMEM]
    call hashAndFillAes1Rx4
    mov  rcx, r12
    mov  edx, 32
    lea  r8, [rbx+VX_REG]
    mov  r9d, REGFILE_SZ
    call blake2b
    add  rsp, 48
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
randomx_calculate_hash_next ENDP

; ---------------------------------------------------------------------------
; randomx_calculate_hash_last (rcx=vm, rdx=output)
; ---------------------------------------------------------------------------
randomx_calculate_hash_last PROC
    push rbx
    push r12
    push r13
    sub  rsp, 48
    mov  rbx, rcx
    mov  r12, rdx
    mov  dword ptr [rsp+32], MXCSR_DEF
    ldmxcsr dword ptr [rsp+32]
    mov  r13d, 7
vhl_loop:
    mov  rcx, rbx
    lea  rdx, [rbx+VX_TMEM]
    call vx_run
    lea  rcx, [rbx+VX_TMEM]
    mov  edx, 64
    lea  r8, [rbx+VX_REG]
    mov  r9d, REGFILE_SZ
    call blake2b
    dec  r13d
    jnz  vhl_loop
    mov  rcx, rbx
    lea  rdx, [rbx+VX_TMEM]
    call vx_run
    mov  rcx, [rbx+VX_SP]
    mov  rdx, SCRATCHPAD_SZ
    lea  r8, [rbx+VX_REGA]
    call hashAes1Rx4
    mov  rcx, r12
    mov  edx, 32
    lea  r8, [rbx+VX_REG]
    mov  r9d, REGFILE_SZ
    call blake2b
    add  rsp, 48
    pop  r13
    pop  r12
    pop  rbx
    ret
randomx_calculate_hash_last ENDP

END
