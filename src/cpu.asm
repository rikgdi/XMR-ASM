; XMRASM : CPU feature detection and topology queries
;
; Exports:
;   cpu_detect     () -> eax feature bitmask
;                    bit0 = SSSE3, bit1 = AES-NI, bit2 = AVX, bit3 = AVX2
;   cpu_count      () -> eax logical processor count (>= 1)
;
; Mirrors RandomX feature checks (engine.cpp DetectCpuFeatures):
;   leaf1 ecx bit9=ssse3, bit25=aes, bits27&28=osxsave&avx_hw then
;   xcr0 bits1-2 set => AVX; leaf7 ebx bit5 => AVX2.

option casemap:none

PUBLIC cpu_detect, cpu_count

EXTERNDEF GetActiveProcessorCount:PROC

.code

; ---------------------------------------------------------------------------
; cpu_detect -> eax bitmask (bit0 ssse3, bit1 aes, bit2 avx, bit3 avx2)
; ---------------------------------------------------------------------------
cpu_detect PROC
    push rbx                        ; cpuid clobbers ebx
    xor eax, eax
    cpuid                           ; eax = max basic leaf
    mov r9d, eax
    xor r8d, r8d
    cmp r9d, 1
    jb cd_done
    mov eax, 1
    xor ecx, ecx
    cpuid                           ; ecx = leaf1 ECX
    test ecx, 200h                  ; bit9 SSSE3
    jz cd_no_ssse3
    or r8d, 1
cd_no_ssse3:
    test ecx, 2000000h              ; bit25 AES-NI
    jz cd_no_aes
    or r8d, 2
cd_no_aes:
    mov eax, ecx
    and eax, 18000000h              ; bits27 osxsave + bit28 avx_hw
    cmp eax, 18000000h
    jne cd_leaf7
    xor ecx, ecx
    xgetbv                          ; eax = XCR0
    and eax, 6                      ; XMM + YMM state
    cmp eax, 6
    jne cd_leaf7
    or r8d, 4                       ; AVX
cd_leaf7:
    cmp r9d, 7
    jb cd_done
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, 20h                   ; leaf7 ebx bit5 AVX2
    jz cd_done
    or r8d, 8
cd_done:
    mov eax, r8d
    pop rbx
    ret
cpu_detect ENDP

; ---------------------------------------------------------------------------
; cpu_count -> eax logical processors (>= 1)
; ---------------------------------------------------------------------------
cpu_count PROC
    sub rsp, 40
    mov ecx, 0FFFFh                 ; ALL_PROCESSOR_THREADS
    call GetActiveProcessorCount
    test eax, eax
    jnz cc_ok
    mov eax, 1
cc_ok:
    add rsp, 40
    ret
cpu_count ENDP

END
