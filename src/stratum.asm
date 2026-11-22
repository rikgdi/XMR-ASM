; XMRASM : Monero stratum protocol (login / job / submit)
; JSON built by concatenation, parsed with the flat json_* scanners.
;
; Worker-block layout (shared with miner.asm, must match):
;   WB_GEN dd | WB_VALID dd | WB_BLOBLEN dd | WB_PAD dd
;   WB_TARGET dq | WB_HEIGHT dq | WB_VM dq | WB_DSQ dq
;   WB_NONCE dd | WB_IDX dd
;   WB_JOBID db 128 | WB_BLOB db 256 | WB_HASH db 32   (total 472, stride 512)

option casemap:none

PUBLIC stratum_build_login, stratum_build_submit, stratum_handle_line
PUBLIC job_init, job_publish, job_invalidate, job_acquire
PUBLIC job_gen, g_session, sj_seed, sj_target, sj_height
PUBLIC g_shares, g_acc, g_rej, g_dropped

EXTERNDEF app_cstr:PROC
EXTERNDEF fmt_u64:PROC
EXTERNDEF print_line:PROC
EXTERNDEF hex_decode:PROC
EXTERNDEF json_find_key:PROC
EXTERNDEF json_get_string:PROC
EXTERNDEF json_get_number:PROC
EXTERNDEF json_value_is_null:PROC
EXTERNDEF InitializeCriticalSection:PROC
EXTERNDEF EnterCriticalSection:PROC
EXTERNDEF LeaveCriticalSection:PROC

WB_GEN      EQU 0
WB_VALID    EQU 4
WB_BLOBLEN  EQU 8
WB_TARGET   EQU 16
WB_HEIGHT   EQU 24
WB_JOBID    EQU 56
WB_BLOB     EQU 184

.data
msg_login_pre db '{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"',0
msg_login_m1  db '","pass":"',0
msg_login_m2  db '","agent":"',0
msg_login_end db '"}}',0
msg_sub_pre   db '{"id":',0
msg_sub_m1    db ',"jsonrpc":"2.0","method":"submit","params":{"id":"',0
msg_sub_m2    db '","job_id":"',0
msg_sub_m3    db '","nonce":"',0
msg_sub_m4    db '","result":"',0
msg_sub_end   db '"}}',0

; REPLACE WITH YOUR MONERO ADDRESS (95-char base58, starts with 4 or 8)
st_wallet db "YOUR_XMR_WALLET_ADDRESS_HERE",0
st_pass   db "x",0
st_agent  db "XMRASM/0.1",0

k_method  db "method",0
k_params  db "params",0
k_id      db "id",0
k_result  db "result",0
k_error   db "error",0
k_job     db "job",0
k_jobid   db "job_id",0
k_blob    db "blob",0
k_target  db "target",0
k_seed    db "seed_hash",0
k_height  db "height",0
v_job     db "job",0

str_hdr     db "job: ",0
str_diff    db " diff ",0
str_hgt     db " height ",0
str_login_ok db "stratum: logged in",0
str_login_fail db "pool login failed",0
str_acc     db "share accepted",0
str_rej     db "share rejected",0

req_id      dd 2

.data?
job_cs      db 40 dup(?)
job_gen     dd ?
job_valid   dd ?
g_session   db 128 dup(?)
job_id      db 128 dup(?)
job_blob    db 256 dup(?)
job_bloblen dd ?
job_target  dq ?
job_height  dq ?
sj_id       db 128 dup(?)
sj_blob     db 256 dup(?)
sj_bloblen  dd ?
sj_target   dq ?
sj_height   dq ?
sj_seed     db 32 dup(?)
g_shares    dq ?
g_acc       dq ?
g_rej       dq ?
g_dropped   dq ?
hexbuf      db 520 dup(?)
tbuf        db 16 dup(?)
job_msg     db 320 dup(?)
tmpbuf      db 64 dup(?)

.code

; ---------------------------------------------------------------------------
; job_init : create the job critical section (call once)
; ---------------------------------------------------------------------------
job_init PROC
    sub rsp, 40
    lea rcx, job_cs
    call InitializeCriticalSection
    add rsp, 40
    ret
job_init ENDP

; ---------------------------------------------------------------------------
; job_publish : copy sj_* temp fields into the active job, bump generation
; ---------------------------------------------------------------------------
job_publish PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 48
    lea rcx, job_cs
    call EnterCriticalSection
    lea rsi, sj_id
    lea rdi, job_id
    mov ecx, 16
    rep movsq
    lea rsi, sj_blob
    lea rdi, job_blob
    mov ecx, 32
    rep movsq
    mov eax, dword ptr [sj_bloblen]
    mov dword ptr [job_bloblen], eax
    mov rax, qword ptr [sj_target]
    mov qword ptr [job_target], rax
    mov rax, qword ptr [sj_height]
    mov qword ptr [job_height], rax
    mov dword ptr [job_valid], 1
    inc dword ptr [job_gen]
    lea rcx, job_cs
    call LeaveCriticalSection
    add rsp, 48
    pop rdi
    pop rsi
    pop rbx
    ret
job_publish ENDP

; ---------------------------------------------------------------------------
; job_invalidate : workers park (valid=0), generation bump
; ---------------------------------------------------------------------------
job_invalidate PROC
    sub rsp, 40
    lea rcx, job_cs
    call EnterCriticalSection
    mov dword ptr [job_valid], 0
    inc dword ptr [job_gen]
    lea rcx, job_cs
    call LeaveCriticalSection
    add rsp, 40
    ret
job_invalidate ENDP

; ---------------------------------------------------------------------------
; job_acquire (rcx=worker block) -> rax = job generation
; ---------------------------------------------------------------------------
job_acquire PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 48
    mov rbx, rcx
    lea rcx, job_cs
    call EnterCriticalSection
    mov eax, dword ptr [job_gen]
    mov dword ptr [rbx+WB_GEN], eax
    mov eax, dword ptr [job_valid]
    mov dword ptr [rbx+WB_VALID], eax
    mov eax, dword ptr [job_bloblen]
    mov dword ptr [rbx+WB_BLOBLEN], eax
    mov rax, qword ptr [job_target]
    mov qword ptr [rbx+WB_TARGET], rax
    mov rax, qword ptr [job_height]
    mov qword ptr [rbx+WB_HEIGHT], rax
    lea rsi, job_id
    lea rdi, [rbx+WB_JOBID]
    mov ecx, 16
    rep movsq
    lea rsi, job_blob
    lea rdi, [rbx+WB_BLOB]
    mov ecx, 32
    rep movsq
    mov eax, dword ptr [rbx+WB_GEN]
    mov dword ptr [rsp+32], eax         ; keep gen across LeaveCS (volatile-safe)
    lea rcx, job_cs
    call LeaveCriticalSection
    mov eax, dword ptr [rsp+32]
    add rsp, 48
    pop rdi
    pop rsi
    pop rbx
    ret
job_acquire ENDP

; ---------------------------------------------------------------------------
; stratum_build_login (rcx=buf) -> rax = length (incl. trailing \n)
; ---------------------------------------------------------------------------
stratum_build_login PROC
    push r12
    push rsi
    push rdi
    sub rsp, 48
    mov r12, rcx
    mov rdi, rcx
    lea rcx, msg_login_pre
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, st_wallet
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, msg_login_m1
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, st_pass
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, msg_login_m2
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, st_agent
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, msg_login_end
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov byte ptr [rdi], 10
    inc rdi
    mov rax, rdi
    sub rax, r12
    add rsp, 48
    pop rdi
    pop rsi
    pop r12
    ret
stratum_build_login ENDP

; ---------------------------------------------------------------------------
; stratum_build_submit (rcx=buf, rdx=jobid, r8=noncehex8, r9=result64hex)
;   -> rax = length (incl. trailing \n).  uses g_session, bumps req_id.
; ---------------------------------------------------------------------------
stratum_build_submit PROC
    push rbx
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov r12, rcx                        ; start
    mov rbx, rdx                        ; jobid
    mov r13, r8                         ; noncehex
    mov r14, r9                         ; result hex
    mov rdi, rcx
    lea rcx, msg_sub_pre
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov eax, dword ptr [req_id]
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    lea rcx, msg_sub_m1
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, g_session
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, msg_sub_m2
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rcx, rbx
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, msg_sub_m3
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rcx, r13
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, msg_sub_m4
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rcx, r14
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, msg_sub_end
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov byte ptr [rdi], 10
    inc rdi
    inc dword ptr [req_id]
    mov rax, rdi
    sub rax, r12
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rbx
    ret
stratum_build_submit ENDP

; ---------------------------------------------------------------------------
; stratum_handle_line (rcx=line) -> rax:
;   0 = nothing / printed, 1 = job in sj_*, 2 = session set,
;   3 = error reported, 4 = session set + job in sj_*
; ---------------------------------------------------------------------------
stratum_handle_line PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48
    mov rbx, rcx
    xor r15d, r15d                      ; got session flag
    ; ---- method? ----
    mov rcx, rbx
    xor edx, edx
    lea r8, k_method
    call json_find_key
    cmp rax, -1
    je  shl_no_method
    mov rcx, rbx
    mov rdx, rax
    lea r8, tmpbuf
    mov r9d, 64
    call json_get_string
    cmp rax, 3
    jne shl_no_method
    mov al, byte ptr [tmpbuf]
    cmp al, 'j'
    jne shl_no_method
    cmp byte ptr [tmpbuf+1], 'o'
    jne shl_no_method
    cmp byte ptr [tmpbuf+2], 'b'
    jne shl_no_method
    ; job notification
    mov rcx, rbx
    xor edx, edx
    lea r8, k_params
    call json_find_key
    cmp rax, -1
    je  shl_none
    mov rcx, rbx
    mov rdx, rax
    call parse_job
    cmp rax, 1
    jne shl_none
    mov eax, 1
    jmp shl_out
shl_no_method:
    ; ---- error? ----
    mov rcx, rbx
    xor edx, edx
    lea r8, k_error
    call json_find_key
    cmp rax, -1
    je  shl_res
    mov rcx, rbx
    mov rdx, rax
    call json_value_is_null
    test eax, eax
    jnz shl_res
    ; non-null error
    mov rcx, rbx
    xor edx, edx
    lea r8, k_id
    call json_find_key
    cmp rax, -1
    je  shl_err
    mov rcx, rbx
    mov rdx, rax
    call json_get_number
    cmp rax, 1
    je  shl_login_fail
shl_err:
    lock inc qword ptr [g_rej]
    lea rcx, str_rej
    call print_line
    mov eax, 3
    jmp shl_out
shl_login_fail:
    lea rcx, str_login_fail
    call print_line
    mov eax, 3
    jmp shl_out
shl_res:
    ; ---- result? ----
    mov rcx, rbx
    xor edx, edx
    lea r8, k_result
    call json_find_key
    cmp rax, -1
    je  shl_none
    mov r12, rax                        ; result pos
    ; session id?
    mov rcx, rbx
    mov rdx, r12
    lea r8, k_id
    call json_find_key
    cmp rax, -1
    je  shl_jobchk
    cmp byte ptr [rbx+rax], '"'
    jne shl_jobchk
    mov rcx, rbx
    mov rdx, rax
    lea r8, g_session
    mov r9d, 128
    call json_get_string
    test rax, rax
    js  shl_jobchk
    mov r15d, 1
    lea rcx, str_login_ok
    call print_line
shl_jobchk:
    mov rcx, rbx
    mov rdx, r12
    lea r8, k_job
    call json_find_key
    cmp rax, -1
    je  shl_noresjob
    mov rcx, rbx
    mov rdx, rax
    call parse_job
    cmp rax, 1
    jne shl_noresjob
    test r15d, r15d
    jz  shl_j1
    mov eax, 4
    jmp shl_out
shl_j1:
    mov eax, 1
    jmp shl_out
shl_noresjob:
    test r15d, r15d
    jz  shl_accepted
    mov eax, 2
    jmp shl_out
shl_accepted:
    lock inc qword ptr [g_acc]
    lea rcx, str_acc
    call print_line
shl_none:
    xor eax, eax
shl_out:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
stratum_handle_line ENDP

; ---------------------------------------------------------------------------
; parse_job (rcx=line, rdx=pos) -> rax = 1 ok / -1 fail ; fills sj_*
; ---------------------------------------------------------------------------
parse_job PROC
    push rbx
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 32
    mov rbx, rcx
    mov r12, rdx
    ; job_id
    mov rcx, rbx
    mov rdx, r12
    lea r8, k_jobid
    call json_find_key
    cmp rax, -1
    je  pj_fail
    mov rcx, rbx
    mov rdx, rax
    lea r8, sj_id
    mov r9d, 128
    call json_get_string
    test rax, rax
    js  pj_fail
    ; blob hex
    mov rcx, rbx
    mov rdx, r12
    lea r8, k_blob
    call json_find_key
    cmp rax, -1
    je  pj_fail
    mov rcx, rbx
    mov rdx, rax
    lea r8, hexbuf
    mov r9d, 520
    call json_get_string
    mov r13, rax                        ; hex len
    cmp r13, 86
    jb  pj_fail
    cmp r13, 512
    ja  pj_fail
    test r13, 1
    jnz pj_fail
    lea rcx, hexbuf
    mov rdx, r13
    lea r8, sj_blob
    call hex_decode
    cmp eax, 1
    jne pj_fail
    mov eax, r13d
    shr eax, 1
    mov dword ptr [sj_bloblen], eax
    cmp eax, 43
    jb  pj_fail
    ; target hex
    mov rcx, rbx
    mov rdx, r12
    lea r8, k_target
    call json_find_key
    cmp rax, -1
    je  pj_fail
    mov rcx, rbx
    mov rdx, rax
    lea r8, hexbuf
    mov r9d, 32
    call json_get_string
    mov r13, rax
    cmp r13, 2
    jb  pj_fail
    cmp r13, 16
    ja  pj_fail
    test r13, 1
    jnz pj_fail
    lea rcx, hexbuf
    mov rdx, r13
    lea r8, tbuf
    call hex_decode
    cmp eax, 1
    jne pj_fail
    mov r14d, r13d
    shr r14d, 1                         ; byte count n
    lea r13, tbuf
    xor eax, eax                        ; u64
    xor edi, edi                        ; i
pj_fold:
    cmp edi, 8
    jae pj_folddone
    cmp edi, r14d
    jae pj_folddone
    movzx edx, byte ptr [r13+rdi]
    mov ecx, edi
    shl ecx, 3
    shl rdx, cl
    or  rax, rdx
    inc edi
    jmp pj_fold
pj_folddone:
    cmp r14d, 8
    jae pj_foldstore
    mov ecx, 8
    sub ecx, r14d
    shl ecx, 3                          ; 8 * (8 - n)
    shl rax, cl
pj_foldstore:
    test rax, rax
    jz  pj_fail
    mov qword ptr [sj_target], rax
    ; seed_hash hex (required)
    mov rcx, rbx
    mov rdx, r12
    lea r8, k_seed
    call json_find_key
    cmp rax, -1
    je  pj_fail
    mov rcx, rbx
    mov rdx, rax
    lea r8, hexbuf
    mov r9d, 128
    call json_get_string
    cmp rax, 64
    jne pj_fail
    lea rcx, hexbuf
    mov rdx, 64
    lea r8, sj_seed
    call hex_decode
    cmp eax, 1
    jne pj_fail
    ; height (optional)
    mov qword ptr [sj_height], 0
    mov rcx, rbx
    mov rdx, r12
    lea r8, k_height
    call json_find_key
    cmp rax, -1
    je  pj_print
    mov rcx, rbx
    mov rdx, rax
    call json_get_number
    cmp rax, -1
    je  pj_print
    mov qword ptr [sj_height], rax
pj_print:
    ; job: <id> diff <D> height <H>
    lea rdi, job_msg
    lea rcx, str_hdr
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, sj_id
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    lea rcx, str_diff
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rcx, qword ptr [sj_target]
    mov rax, -1
    xor edx, edx
    div rcx                             ; UINT64_MAX / target
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    lea rcx, str_hgt
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rax, qword ptr [sj_height]
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    mov byte ptr [rdi], 0
    lea rcx, job_msg
    call print_line
    mov eax, 1
    jmp pj_out
pj_fail:
    mov eax, -1
pj_out:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rbx
    ret
parse_job ENDP

END
