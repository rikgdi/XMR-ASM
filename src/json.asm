; XMRASM : minimal JSON scanners for stratum messages
; NUL-terminated line buffers.  No full parse tree - flat key lookup
; from a given start offset is enough for the stratum dialect.

option casemap:none

PUBLIC json_find_key, json_get_string, json_get_number, json_value_is_null
PUBLIC json_find_byte

.code

; ---------------------------------------------------------------------------
; json_find_key (rcx=buf, rdx=start, r8=key) -> rax = offset of first value
;   byte after `"<key>"` (ws): ws `:` ws  | -1 if not found.
;   key is NUL-terminated.
; ---------------------------------------------------------------------------
json_find_key PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 40
    mov rbx, rcx                        ; buf
    mov rsi, rdx                        ; cursor
    mov rdi, r8                         ; key
    xor eax, eax
jfk_klen:
    cmp byte ptr [rdi+rax], 0
    je  jfk_kl_done
    inc rax
    jmp jfk_klen
jfk_kl_done:
    mov r12, rax                        ; keylen
jfk_scan:
    mov al, byte ptr [rbx+rsi]
    test al, al
    jz  jfk_fail
    cmp al, '"'
    je  jfk_quote
    inc rsi
    jmp jfk_scan
jfk_quote:
    xor ecx, ecx
jfk_cmp:
    cmp rcx, r12
    je  jfk_closeq
    lea rdx, [rsi+rcx+1]
    mov al, byte ptr [rbx+rdx]
    cmp al, byte ptr [rdi+rcx]
    jne jfk_next
    inc rcx
    jmp jfk_cmp
jfk_closeq:
    lea rdx, [rsi+rcx+1]
    cmp byte ptr [rbx+rdx], '"'
    jne jfk_next
    lea rsi, [rsi+rcx+2]                ; past `"key"`
jfk_ws1:
    mov al, byte ptr [rbx+rsi]
    test al, al
    jz  jfk_fail
    cmp al, ' '
    je  jfk_w1
    cmp al, 9
    je  jfk_w1
    cmp al, 10
    je  jfk_w1
    cmp al, 13
    je  jfk_w1
    jmp jfk_colon
jfk_w1:
    inc rsi
    jmp jfk_ws1
jfk_colon:
    cmp al, ':'
    jne jfk_next
    inc rsi
jfk_ws2:
    mov al, byte ptr [rbx+rsi]
    test al, al
    jz  jfk_fail
    cmp al, ' '
    je  jfk_w2
    cmp al, 9
    je  jfk_w2
    cmp al, 10
    je  jfk_w2
    cmp al, 13
    je  jfk_w2
    jmp jfk_hit
jfk_w2:
    inc rsi
    jmp jfk_ws2
jfk_hit:
    mov rax, rsi
    jmp jfk_out
jfk_next:
    inc rsi
    jmp jfk_scan
jfk_fail:
    mov rax, -1
jfk_out:
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
json_find_key ENDP

; ---------------------------------------------------------------------------
; json_get_string (rcx=buf, rdx=pos, r8=dst, r9=cap) -> rax = len | -1
;   pos may point at whitespace or the opening quote.  Unescapes the common
;   sequences; NUL-terminates dst.  cap includes terminator.
; ---------------------------------------------------------------------------
json_get_string PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 32
    mov rbx, rcx
    mov rsi, rdx
    mov r12, r8
    mov r13, r9
jgs_ws:
    mov al, byte ptr [rbx+rsi]
    cmp al, ' '
    je  jgs_wsi
    cmp al, 9
    je  jgs_wsi
    cmp al, 10
    je  jgs_wsi
    cmp al, 13
    je  jgs_wsi
    jmp jgs_chk
jgs_wsi:
    inc rsi
    jmp jgs_ws
jgs_chk:
    cmp al, '"'
    jne jgs_fail
    inc rsi
    xor rdi, rdi                        ; written
jgs_loop:
    mov al, byte ptr [rbx+rsi]
    test al, al
    jz  jgs_fail
    cmp al, '"'
    je  jgs_done
    cmp al, '\'
    je  jgs_esc
    mov rcx, r13
    dec rcx
    cmp rdi, rcx
    jae jgs_fail                        ; overflow
    mov byte ptr [r12+rdi], al
    inc rdi
    inc rsi
    jmp jgs_loop
jgs_esc:
    inc rsi
    mov al, byte ptr [rbx+rsi]
    test al, al
    jz  jgs_fail
    cmp al, 'u'
    je  jgs_uni
    ; simple escape: map to the character itself (covers " \ / )
    cmp al, 'n'
    jne jgs_e1
    mov al, 10
    jmp jgs_eemit
jgs_e1:
    cmp al, 'r'
    jne jgs_e2
    mov al, 13
    jmp jgs_eemit
jgs_e2:
    cmp al, 't'
    jne jgs_e3
    mov al, 9
    jmp jgs_eemit
jgs_e3:
    cmp al, 'b'
    jne jgs_e4
    mov al, 8
    jmp jgs_eemit
jgs_e4:
    cmp al, 'f'
    jne jgs_eemit
    mov al, 12
jgs_eemit:
    inc rsi                             ; past escape char
    mov rcx, r13
    dec rcx
    cmp rdi, rcx
    jae jgs_fail
    mov byte ptr [r12+rdi], al
    inc rdi
    jmp jgs_loop
jgs_uni:
    ; rsi at 'u' ; hex digits at rsi+1..rsi+4 ; decode if < 0x80 else '?'
    xor edx, edx
    xor ecx, ecx
jgs_u4:
    cmp rcx, 4
    je  jgs_udone
    lea r9, [rsi+rcx+1]
    mov al, byte ptr [rbx+r9]
    ; nibble
    cmp al, '0'
    jb  jgs_ubad
    cmp al, '9'
    jbe jgs_udig
    or  al, 20h
    cmp al, 'a'
    jb  jgs_ubad
    cmp al, 'f'
    ja  jgs_ubad
    sub al, 'a' - 10
    jmp jgs_uacc
jgs_udig:
    sub al, '0'
jgs_uacc:
    movzx eax, al
    shl edx, 4
    or  edx, eax
    inc rcx
    jmp jgs_u4
jgs_ubad:
    mov edx, 3Fh                        ; '?' fallback
jgs_udone:
    add rsi, 5                          ; past uXXXX
    cmp edx, 80h
    jb  jgs_uemit
    mov edx, '?'
jgs_uemit:
    mov rcx, r13
    dec rcx
    cmp rdi, rcx
    jae jgs_fail
    mov byte ptr [r12+rdi], dl
    inc rdi
    jmp jgs_loop
jgs_done:
    mov byte ptr [r12+rdi], 0
    mov rax, rdi
    jmp jgs_out
jgs_fail:
    mov rax, -1
jgs_out:
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
json_get_string ENDP

; ---------------------------------------------------------------------------
; json_get_number (rcx=buf, rdx=pos) -> rax = value | -1
; ---------------------------------------------------------------------------
json_get_number PROC
    push rbx
    push rsi
    sub rsp, 40
    mov rbx, rcx
    mov rsi, rdx
    xor r8d, r8d                        ; negative flag
jgn_ws:
    mov al, byte ptr [rbx+rsi]
    cmp al, ' '
    je  jgn_wsi
    cmp al, 9
    je  jgn_wsi
    cmp al, 10
    je  jgn_wsi
    cmp al, 13
    je  jgn_wsi
    jmp jgn_sign
jgn_wsi:
    inc rsi
    jmp jgn_ws
jgn_sign:
    cmp al, '-'
    jne jgn_digchk
    mov r8d, 1
    inc rsi
    mov al, byte ptr [rbx+rsi]
jgn_digchk:
    cmp al, '0'
    jb  jgn_fail
    cmp al, '9'
    ja  jgn_fail
    xor eax, eax
jgn_loop:
    movzx edx, byte ptr [rbx+rsi]
    cmp dl, '0'
    jb  jgn_end
    cmp dl, '9'
    ja  jgn_end
    imul rax, rax, 10
    sub dl, '0'
    movzx edx, dl
    add rax, rdx
    inc rsi
    jmp jgn_loop
jgn_end:
    test r8d, r8d
    jz  jgn_out
    neg rax
    jmp jgn_out
jgn_fail:
    mov rax, -1
jgn_out:
    add rsp, 40
    pop rsi
    pop rbx
    ret
json_get_number ENDP

; ---------------------------------------------------------------------------
; json_value_is_null (rcx=buf, rdx=pos) -> rax = 1 if "null" at pos
; ---------------------------------------------------------------------------
json_value_is_null PROC
    mov eax, dword ptr [rcx+rdx]
    cmp eax, 6C6C756Eh                  ; "null" little-endian
    jne jvn_no
    mov eax, 1
    ret
jvn_no:
    xor eax, eax
    ret
json_value_is_null ENDP

; ---------------------------------------------------------------------------
; json_find_byte (rcx=buf, rdx=len, r8=byte) -> rax = index | -1
; ---------------------------------------------------------------------------
json_find_byte PROC
    xor eax, eax
jfb_loop:
    cmp rax, rdx
    jae jfb_miss
    mov r9, rax
    cmp byte ptr [rcx+r9], r8b
    je  jfb_hit
    inc rax
    jmp jfb_loop
jfb_hit:
    ret
jfb_miss:
    mov rax, -1
    ret
json_find_byte ENDP

END
