; XMRASM : console output and formatting helpers
; All functions use the Microsoft x64 calling convention.

option casemap:none

PUBLIC console_init, console_write, print_cstr, print_line
PUBLIC fmt_u64, fmt_hex64, fmt_hex32, fmt_hex_bytes, hex_decode, app_cstr

EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC

STD_OUTPUT_HANDLE EQU -11

.data?
std_handle   dq ?
written      dq ?
fmt_tmp      db 32 dup(?)

.data
hex_lower    db "0123456789abcdef"
crlf         db 13,10

.code

; ---------------------------------------------------------------------------
; console_init : cache stdout handle. call once at startup.
; ---------------------------------------------------------------------------
console_init PROC
    sub rsp, 40
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov std_handle, rax
    add rsp, 40
    ret
console_init ENDP

; ---------------------------------------------------------------------------
; console_write : write buffer of given length to stdout
;   rcx = buffer, rdx = length
; ---------------------------------------------------------------------------
console_write PROC
    sub rsp, 56
    mov r8, rdx                     ; nNumberOfBytesToWrite
    mov rdx, rcx                    ; lpBuffer
    mov rcx, std_handle             ; hFile
    lea r9, written                 ; lpNumberOfBytesWritten
    mov qword ptr [rsp+32], 0       ; lpOverlapped
    call WriteFile
    add rsp, 56
    ret
console_write ENDP

; ---------------------------------------------------------------------------
; print_cstr : write NUL-terminated string to stdout
;   rcx = string
; ---------------------------------------------------------------------------
print_cstr PROC
    push rbx
    sub rsp, 32
    mov rbx, rcx
    xor eax, eax
@@:
    cmp byte ptr [rbx+rax], 0
    je @F
    inc rax
    jmp @B
@@:
    mov rdx, rax
    mov rcx, rbx
    call console_write
    add rsp, 32
    pop rbx
    ret
print_cstr ENDP

; ---------------------------------------------------------------------------
; print_line : write NUL-terminated string + CRLF to stdout
;   rcx = string
; ---------------------------------------------------------------------------
print_line PROC
    push rbx
    sub rsp, 32
    mov rbx, rcx
    xor eax, eax
@@:
    cmp byte ptr [rbx+rax], 0
    je @F
    inc rax
    jmp @B
@@:
    mov rdx, rax
    mov rcx, rbx
    call console_write
    lea rcx, crlf
    mov rdx, 2
    call console_write
    add rsp, 32
    pop rbx
    ret
print_line ENDP

; ---------------------------------------------------------------------------
; fmt_u64 : format unsigned 64-bit value as decimal
;   rax = value, rcx = destination buffer (>= 21 bytes)
; returns rax = number of bytes written (no NUL appended)
; ---------------------------------------------------------------------------
fmt_u64 PROC
    push rbx
    sub rsp, 48
    mov rbx, rcx
    lea r11, [rsp+32]              ; temp digit area (reverse)
    mov byte ptr [r11], 0
    xor r8, r8                      ; digit count
    mov r9, 10
    mov r10, rax
@@:
    xor rdx, rdx
    div r9
    add dl, '0'
    mov [r11+r8], dl
    inc r8
    test rax, rax
    jnz @B
    ; reverse into rbx
    mov rcx, r8
    xor rax, rax
@@:
    dec rcx
    mov dl, [r11+rcx]
    mov [rbx+rax], dl
    inc rax
    test rcx, rcx
    jnz @B
    add rsp, 48
    pop rbx
    ret
fmt_u64 ENDP

; ---------------------------------------------------------------------------
; fmt_hex64 : format unsigned 64-bit value as 16 lowercase hex chars (no 0x)
;   rax = value, rcx = destination buffer (>= 16 bytes)
; ---------------------------------------------------------------------------
fmt_hex64 PROC
    lea r9, hex_lower
    mov r10, 16
@@:
    dec r10
    mov rdx, rax
    and edx, 0Fh
    mov dl, [r9+rdx]
    mov [rcx+r10], dl
    shr rax, 4
    test r10, r10
    jnz @B
    mov eax, 16
    ret
fmt_hex64 ENDP

; ---------------------------------------------------------------------------
; fmt_hex32 : format unsigned 32-bit value as 8 lowercase hex chars
;   ecx = value, rdx = destination buffer (>= 8 bytes)
; ---------------------------------------------------------------------------
fmt_hex32 PROC
    mov eax, ecx
    mov rcx, rdx
    mov r10d, 8
    lea r9, hex_lower
@@:
    dec r10
    mov rdx, rax
    and edx, 0Fh
    mov dl, [r9+rdx]
    mov [rcx+r10], dl
    shr rax, 4
    test r10, r10
    jnz @B
    mov eax, 8
    ret
fmt_hex32 ENDP

; ---------------------------------------------------------------------------
; fmt_hex_bytes : format byte buffer as lowercase hex
;   rcx = bytes, rdx = count, r8 = destination (>= 2*count bytes)
; returns rax = bytes written
; ---------------------------------------------------------------------------
fmt_hex_bytes PROC
    lea r10, hex_lower
    xor rax, rax
    test rdx, rdx
    jz @F
@@:
    movzx r9, byte ptr [rcx]
    mov r11d, r9d
    shr r11d, 4
    mov r9b, [r10+r11]             ; hi nibble char
    mov [r8+rax], r9b
    inc rax
    and r11b, 0Fh
    movzx r9, byte ptr [rcx]
    and r9b, 0Fh
    mov r9b, [r10+r9]
    mov [r8+rax], r9b
    inc rax
    inc rcx
    dec rdx
    jnz @B
@@:
    ret
fmt_hex_bytes ENDP

; ---------------------------------------------------------------------------
; app_cstr : append NUL-terminated string to buffer (no terminator written)
;   rcx = src, rdx = dst
; returns rax = bytes copied
; ---------------------------------------------------------------------------
app_cstr PROC
    sub rsp, 40
    xor eax, eax
ac_loop:
    mov r8b, byte ptr [rcx+rax]
    test r8b, r8b
    jz  ac_done
    mov byte ptr [rdx+rax], r8b
    inc rax
    jmp ac_loop
ac_done:
    add rsp, 40
    ret
app_cstr ENDP

; ---------------------------------------------------------------------------
; hex_decode : decode ASCII hex string to bytes
;   rcx = hex string, rdx = string length (even), r8 = output buffer
; returns rax = 1 on success, 0 on invalid input
; accepts 0-9 a-f A-F
; ---------------------------------------------------------------------------
hex_decode PROC
    xor eax, eax
    test rdx, rdx
    jz @F
    test rdx, 1
    jnz fail                        ; odd length
@@:
    xor r9, r9
loop_top:
    cmp r9, rdx
    jae success
    ; high nibble
    movzx r10d, byte ptr [rcx+r9]
    inc r9
    call nibble                     ; -> eax (0..15) or -1
    cmp eax, -1
    je fail
    mov r11d, eax
    shl r11d, 4
    ; low nibble
    movzx r10d, byte ptr [rcx+r9]
    inc r9
    call nibble
    cmp eax, -1
    je fail
    or r11b, al
    lea rax, [r9-2]                 ; chars consumed so far - 2
    shr rax, 1                      ; byte index
    mov [r8+rax], r11b
    jmp loop_top
success:
    mov eax, 1
    ret
fail:
    xor eax, eax
    ret
hex_decode ENDP

; nibble: r10d = char -> eax = value or -1. clobbers r10d only besides eax
nibble PROC
    cmp r10b, '0'
    jb nib_bad
    cmp r10b, '9'
    jbe nib_digit
    or r10b, 20h                    ; to lowercase
    cmp r10b, 'a'
    jb nib_bad
    cmp r10b, 'f'
    ja nib_bad
    sub r10b, 'a' - 10
    movzx eax, r10b
    ret
nib_digit:
    sub r10b, '0'
    movzx eax, r10b
    ret
nib_bad:
    mov eax, -1
    ret
nibble ENDP

END
