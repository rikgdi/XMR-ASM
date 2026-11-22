; XMRASM : mining orchestration
;   miner_run : alloc cache+dataset, spawn worker threads + stratum thread,
;   stats loop, shutdown.  Workers hash one nonce per iteration using
;   randomx_calculate_hash and push shares; the stratum thread submits them.

option casemap:none

PUBLIC miner_run, miner_on_job

EXTERNDEF print_line:PROC
EXTERNDEF app_cstr:PROC
EXTERNDEF fmt_u64:PROC
EXTERNDEF fmt_hex32:PROC
EXTERNDEF fmt_hex_bytes:PROC
EXTERNDEF net_startup:PROC
EXTERNDEF net_connect:PROC
EXTERNDEF net_send_all:PROC
EXTERNDEF net_wait_read:PROC
EXTERNDEF net_recv:PROC
EXTERNDEF net_close:PROC
EXTERNDEF stratum_build_login:PROC
EXTERNDEF stratum_build_submit:PROC
EXTERNDEF stratum_handle_line:PROC
EXTERNDEF job_init:PROC
EXTERNDEF job_publish:PROC
EXTERNDEF job_invalidate:PROC
EXTERNDEF job_acquire:PROC
EXTERNDEF json_find_byte:PROC
EXTERNDEF randomx_alloc_cache:PROC
EXTERNDEF randomx_init_cache:PROC
EXTERNDEF randomx_alloc_dataset:PROC
EXTERNDEF randomx_get_dataset_memory:PROC
EXTERNDEF randomx_init_dataset:PROC
EXTERNDEF randomx_create_vm:PROC
EXTERNDEF randomx_calculate_hash:PROC
EXTERNDEF mem_alloc:PROC
EXTERNDEF cpu_count:PROC
EXTERNDEF job_gen:DWORD
EXTERNDEF sj_seed:BYTE
EXTERNDEF g_shares:QWORD
EXTERNDEF g_acc:QWORD
EXTERNDEF g_rej:QWORD
EXTERNDEF g_dropped:QWORD
EXTERNDEF CreateThread:PROC
EXTERNDEF WaitForSingleObject:PROC
EXTERNDEF Sleep:PROC
EXTERNDEF SetConsoleCtrlHandler:PROC
EXTERNDEF GetTickCount64:PROC
EXTERNDEF InitializeCriticalSection:PROC
EXTERNDEF EnterCriticalSection:PROC
EXTERNDEF LeaveCriticalSection:PROC
EXTERNDEF g_init_progress:QWORD

; worker-block layout (must match stratum.asm)
WB_GEN      EQU 0
WB_VALID    EQU 4
WB_BLOBLEN  EQU 8
WB_TARGET   EQU 16
WB_HEIGHT   EQU 24
WB_VM       EQU 32
WB_DSQ      EQU 40
WB_NONCE    EQU 48
WB_IDX      EQU 52
WB_JOBID    EQU 56
WB_BLOB     EQU 184
WB_HASH     EQU 440
WB_STRIDE   EQU 512

; share layout
SH_NONCE    EQU 128
SH_HASH     EQU 132
SH_STRIDE   EQU 176
SHARE_CAP   EQU 64

; init-thread param layout
IP_STRIDE   EQU 32

TOTAL_ITEMS EQU 34078719

.data
st_host     db "pool.supportxmr.com",0
st_port     db "3333",0
str_start   db "miner: starting",0
str_conn    db "stratum: connecting",0
str_ok      db "stratum: connected",0
str_retry   db "stratum: retry in 5s",0
str_initds  db "dataset: initializing...",0
str_dsready db "dataset: ready",0
str_nomem   db "error: out of memory",0
str_wsa     db "error: winsock startup failed",0
str_stop    db "miner: stopped",0
st_hr1      db "hashrate ",0
st_hr2      db " H/s | found ",0
st_hr3      db " accepted ",0
st_hr4      db " rejected ",0
st_hr5      db " dropped ",0
st_mem1     db "memory budget: ",0
st_mem2     db " MB (cap 4096 MB)",0
st_initp    db "dataset: initializing ",0
str_budget  db "error: memory budget exceeded (4096 MB)",0

.data?
g_running   dd ?
g_tcount    dd ?
g_cache     dq ?
g_dataset   dq ?
g_dsmem     dq ?
g_ds_ready  dd ?
g_init_busy dd ?
g_workers   dq ?
g_neth      dq ?
g_whandles  dq 64 dup(?)
g_curseed   db 32 dup(?)
g_hashes    dq ?
g_last_rx   dq ?
share_cs    db 40 dup(?)
share_head  dd ?
share_tail  dd ?
share_count dd ?
share_store db SHARE_CAP * SH_STRIDE dup(?)
init_params db 16 * IP_STRIDE dup(?)
init_handles dq 16 dup(?)
recv_buf    db 4096 dup(?)
pend_buf    db 16384 dup(?)
pend_len    dd ?
linebuf     db 4096 dup(?)
sendbuf     db 2048 dup(?)
share_tmp   db SH_STRIDE dup(?)
nonce_hex   db 16 dup(?)
result_hex  db 80 dup(?)
statbuf     db 256 dup(?)

.code

; ---------------------------------------------------------------------------
; thread_create (rcx=start, rdx=param) -> rax = handle | 0
; ---------------------------------------------------------------------------
thread_create PROC
    push rbx
    sub rsp, 64
    mov r8, rcx                         ; lpStartAddress
    mov r9, rdx                         ; lpParameter
    xor ecx, ecx                        ; lpThreadAttributes
    xor edx, edx                        ; dwStackSize
    mov qword ptr [rsp+32], 0           ; dwCreationFlags
    mov qword ptr [rsp+40], 0           ; lpThreadId
    call CreateThread
    add rsp, 64
    pop rbx
    ret
thread_create ENDP

; ---------------------------------------------------------------------------
; share_init
; ---------------------------------------------------------------------------
share_init PROC
    sub rsp, 40
    lea rcx, share_cs
    call InitializeCriticalSection
    add rsp, 40
    ret
share_init ENDP

; ---------------------------------------------------------------------------
; share_push (rcx=jobid, edx=nonce, r8=hash) -> rax = 1 ok / 0 full
; ---------------------------------------------------------------------------
share_push PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 40
    mov r12, rcx                        ; jobid
    mov r13d, edx                       ; nonce
    mov rbx, r8                         ; hash
    lea rcx, share_cs
    call EnterCriticalSection
    cmp dword ptr [share_count], SHARE_CAP
    jae sp_drop
    mov eax, dword ptr [share_tail]
    imul rax, SH_STRIDE
    lea rdi, share_store
    add rdi, rax
    mov rsi, r12
    mov ecx, 16
    rep movsq
    mov dword ptr [rdi], r13d
    add rdi, 4
    mov rsi, rbx
    mov ecx, 4
    rep movsq
    mov eax, dword ptr [share_tail]
    inc eax
    and eax, SHARE_CAP - 1
    mov dword ptr [share_tail], eax
    inc dword ptr [share_count]
    mov r14d, 1
    jmp sp_out
sp_drop:
    lock inc qword ptr [g_dropped]
    xor r14d, r14d
sp_out:
    lea rcx, share_cs
    call LeaveCriticalSection
    mov eax, r14d
    add rsp, 40
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
share_push ENDP

; ---------------------------------------------------------------------------
; share_pop (rcx=dst) -> rax = 1 got / 0 empty
; ---------------------------------------------------------------------------
share_pop PROC
    push rbx
    push rsi
    push rdi
    push r14
    sub rsp, 40
    mov rbx, rcx
    lea rcx, share_cs
    call EnterCriticalSection
    cmp dword ptr [share_count], 0
    je  spp_empty
    mov eax, dword ptr [share_head]
    imul rax, SH_STRIDE
    lea rsi, share_store
    add rsi, rax
    mov rdi, rbx
    mov ecx, 21                         ; 168 bytes >= 164 used
    rep movsq
    mov eax, dword ptr [share_head]
    inc eax
    and eax, SHARE_CAP - 1
    mov dword ptr [share_head], eax
    dec dword ptr [share_count]
    mov r14d, 1
    jmp spp_out
spp_empty:
    xor r14d, r14d
spp_out:
    lea rcx, share_cs
    call LeaveCriticalSection
    mov eax, r14d
    add rsp, 40
    pop r14
    pop rdi
    pop rsi
    pop rbx
    ret
share_pop ENDP

; ---------------------------------------------------------------------------
; init_worker (rcx=param {cache, ds, start, count})
; ---------------------------------------------------------------------------
init_worker PROC
    push rbx
    sub rsp, 48
    mov rbx, rcx
    mov rcx, qword ptr [rbx+8]           ; dataset
    mov rdx, qword ptr [rbx+0]           ; cache
    mov r8d, dword ptr [rbx+16]          ; start
    mov r9d, dword ptr [rbx+20]          ; count
    call randomx_init_dataset
    xor eax, eax
    add rsp, 48
    pop rbx
    ret
init_worker ENDP

; ---------------------------------------------------------------------------
; dataset_reinit (rcx=seed32) -> rax = 1
; ---------------------------------------------------------------------------
dataset_reinit PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48
    mov r12, rcx                        ; seed
    lea rcx, str_initds
    call print_line
    mov dword ptr [g_init_busy], 1
    mov rcx, qword ptr [g_cache]
    mov rdx, r12
    mov r8d, 32
    call randomx_init_cache
    ; n = clamp(tcount,1,16)
    mov eax, dword ptr [g_tcount]
    cmp eax, 1
    jge dr_n1
    mov eax, 1
dr_n1:
    cmp eax, 16
    jle dr_n2
    mov eax, 16
dr_n2:
    mov r14d, eax                       ; n
    ; chunk = TOTAL / n ; rem = TOTAL % n
    mov eax, TOTAL_ITEMS
    xor edx, edx
    div r14d
    mov ebx, eax                        ; chunk
    mov r13d, edx                       ; rem
    xor r15d, r15d
dr_fill:
    cmp r15d, r14d
    jae dr_run
    imul rax, r15, IP_STRIDE
    lea rdi, init_params
    add rdi, rax
    mov rcx, qword ptr [g_cache]
    mov qword ptr [rdi+0], rcx
    mov rcx, qword ptr [g_dataset]
    mov qword ptr [rdi+8], rcx
    mov eax, ebx
    imul eax, r15d
    mov dword ptr [rdi+16], eax         ; start
    mov eax, ebx
    lea ecx, [r14-1]
    cmp r15d, ecx
    jne dr_store
    add eax, r13d
dr_store:
    mov dword ptr [rdi+20], eax         ; count
    inc r15d
    jmp dr_fill
dr_run:
    xor r15d, r15d
    lea r13, init_handles
dr_create:
    cmp r15d, r14d
    jae dr_wait
    imul rax, r15, IP_STRIDE
    lea rdx, init_params
    add rdx, rax
    lea rcx, init_worker
    call thread_create
    mov qword ptr [r13+r15*8], rax
    inc r15d
    jmp dr_create
dr_wait:
    xor r15d, r15d
dr_wloop:
    cmp r15d, r14d
    jae dr_done
    mov rcx, qword ptr [r13+r15*8]
    mov edx, -1
    call WaitForSingleObject
    inc r15d
    jmp dr_wloop
dr_done:
    mov dword ptr [g_init_busy], 0
    mov dword ptr [g_ds_ready], 1
    lea rcx, str_dsready
    call print_line
    mov eax, 1
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
dataset_reinit ENDP

; ---------------------------------------------------------------------------
; worker_proc (rcx=block)
; ---------------------------------------------------------------------------
worker_proc PROC
    push rbx
    push r12
    push r14
    push r15
    sub rsp, 40
    mov r12, rcx
    mov r14d, -1                        ; my generation
    xor r15d, r15d                      ; nonce
w_top:
    cmp dword ptr [g_running], 0
    je  w_exit
    cmp dword ptr [g_init_busy], 0
    jne w_park
    cmp dword ptr [g_ds_ready], 0
    je  w_park
    mov eax, dword ptr [job_gen]
    cmp eax, r14d
    je  w_hash
    mov rcx, r12
    call job_acquire
    mov r14d, eax
    cmp dword ptr [r12+WB_VALID], 0
    je  w_park
    cmp dword ptr [r12+WB_BLOBLEN], 43
    jb  w_park
    cmp qword ptr [r12+WB_VM], 0
    jne w_seed
    mov ecx, 14
    xor edx, edx
    lea r8, [r12+WB_DSQ]
    call randomx_create_vm
    test rax, rax
    jz  w_park
    mov qword ptr [r12+WB_VM], rax
w_seed:
    mov eax, 811C9DC5h                  ; FNV-1a offset basis
    lea rbx, [r12+WB_JOBID]
w_fnv:
    movzx edx, byte ptr [rbx]
    test dl, dl
    jz  w_fnvd
    xor eax, edx
    imul eax, 16777619
    inc rbx
    jmp w_fnv
w_fnvd:
    add eax, dword ptr [r12+WB_IDX]
    mov dword ptr [r12+WB_NONCE], eax
w_hash:
    mov eax, dword ptr [r12+WB_NONCE]
    lea rbx, [r12+WB_BLOB+39]
    mov dword ptr [rbx], eax
    mov rcx, qword ptr [r12+WB_VM]
    lea rdx, [r12+WB_BLOB]
    mov r8d, dword ptr [r12+WB_BLOBLEN]
    lea r9, [r12+WB_HASH]
    call randomx_calculate_hash
    mov rax, qword ptr [r12+WB_HASH+24]
    cmp rax, qword ptr [r12+WB_TARGET]
    ja  w_count
    lea rcx, [r12+WB_JOBID]
    mov edx, dword ptr [r12+WB_NONCE]
    lea r8, [r12+WB_HASH]
    call share_push
    test eax, eax
    jz  w_count
    lock inc qword ptr [g_shares]
w_count:
    lock add qword ptr [g_hashes], 1
    mov eax, dword ptr [r12+WB_NONCE]
    add eax, dword ptr [g_tcount]
    mov dword ptr [r12+WB_NONCE], eax
    jmp w_top
w_park:
    mov ecx, 50
    call Sleep
    mov r14d, -1
    jmp w_top
w_exit:
    xor eax, eax
    add rsp, 40
    pop r15
    pop r14
    pop r12
    pop rbx
    ret
worker_proc ENDP

; ---------------------------------------------------------------------------
; miner_on_job : seed check + dataset (re)init + publish parsed job
; ---------------------------------------------------------------------------
miner_on_job PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 40
    mov eax, dword ptr [g_ds_ready]
    test eax, eax
    jz  mj_init
    lea rsi, sj_seed
    lea rdi, g_curseed
    mov ecx, 4
    repe cmpsq
    je  mj_publish
mj_init:
    call job_invalidate
    lea rcx, sj_seed
    call dataset_reinit
    lea rsi, sj_seed
    lea rdi, g_curseed
    mov ecx, 4
    rep movsq
mj_publish:
    call job_publish
    xor eax, eax
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
miner_on_job ENDP

; ---------------------------------------------------------------------------
; net_thread (rcx=0)
; ---------------------------------------------------------------------------
net_thread PROC
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 40
nt_start:
    cmp dword ptr [g_running], 0
    je  nt_exit
    lea rcx, str_conn
    call print_line
    lea rcx, st_host
    lea rdx, st_port
    call net_connect
    mov r12, rax
    cmp r12, -1
    je  nt_retry
    lea rcx, str_ok
    call print_line
    lea rcx, sendbuf
    call stratum_build_login
    mov rcx, r12
    lea rdx, sendbuf
    mov r8, rax
    call net_send_all
    test eax, eax
    jz  nt_close
    call GetTickCount64
    mov qword ptr [g_last_rx], rax
    mov dword ptr [pend_len], 0
nt_io:
    cmp dword ptr [g_running], 0
    je  nt_close
nt_drain:
    lea rcx, share_tmp
    call share_pop
    test eax, eax
    jz  nt_wait
    mov ecx, dword ptr [share_tmp+SH_NONCE]
    bswap ecx
    lea rdx, nonce_hex
    call fmt_hex32
    mov byte ptr [nonce_hex+8], 0
    lea rcx, [share_tmp+SH_HASH]
    mov edx, 32
    lea r8, result_hex
    call fmt_hex_bytes
    mov byte ptr [result_hex+64], 0
    lea rcx, sendbuf
    lea rdx, share_tmp
    lea r8, nonce_hex
    lea r9, result_hex
    call stratum_build_submit
    mov rcx, r12
    lea rdx, sendbuf
    mov r8, rax
    call net_send_all
    test eax, eax
    jz  nt_close
    jmp nt_drain
nt_wait:
    mov rcx, r12
    mov edx, 250
    call net_wait_read
    test eax, eax
    jnz nt_recv
    call GetTickCount64
    sub rax, qword ptr [g_last_rx]
    cmp rax, 300000
    ja  nt_close
    jmp nt_io
nt_recv:
    mov rcx, r12
    lea rdx, recv_buf
    mov r8d, 4096
    call net_recv
    test rax, rax
    jle nt_close
    mov r9, rax                         ; n (no calls next)
    mov r8d, dword ptr [pend_len]
    mov r10, r9
    add r10, r8
    cmp r10, 16384
    ja  nt_close
    lea rdi, pend_buf
    add rdi, r8
    lea rsi, recv_buf
    mov rcx, r9
    rep movsb
    add r8, r9
    mov dword ptr [pend_len], r8d
    call GetTickCount64
    mov qword ptr [g_last_rx], rax
nt_lines:
    lea rcx, pend_buf
    mov edx, dword ptr [pend_len]
    mov r8d, 10
    call json_find_byte
    cmp rax, -1
    je  nt_io
    mov r13, rax                        ; index of '\n'
    cmp r13, 4095
    ja  nt_shift
    mov ecx, r13d
    lea rsi, pend_buf
    lea rdi, linebuf
    rep movsb
    mov byte ptr [rdi], 0
    test r13, r13
    jz  nt_handle
    cmp byte ptr [rdi-1], 13
    jne nt_handle
    mov byte ptr [rdi-1], 0
nt_handle:
    lea rcx, linebuf
    call stratum_handle_line
    cmp eax, 1
    je  nt_job
    cmp eax, 4
    je  nt_job
    jmp nt_shift
nt_job:
    call miner_on_job
nt_shift:
    lea rsi, pend_buf
    add rsi, r13
    inc rsi
    lea rdi, pend_buf
    mov ecx, dword ptr [pend_len]
    mov r8d, r13d
    inc r8d
    sub ecx, r8d
    mov dword ptr [pend_len], ecx
    test ecx, ecx
    jle nt_lines
    rep movsb
    jmp nt_lines
nt_close:
    mov rcx, r12
    call net_close
nt_retry:
    lea rcx, str_retry
    call print_line
    mov ecx, 5000
    call Sleep
    jmp nt_start
nt_exit:
    xor eax, eax
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    ret
net_thread ENDP

; ---------------------------------------------------------------------------
; ctrl_handler (rcx=type) -> eax = 1
; ---------------------------------------------------------------------------
ctrl_handler PROC
    mov dword ptr [g_running], 0
    mov eax, 1
    ret
ctrl_handler ENDP

; ---------------------------------------------------------------------------
; miner_run -> rax = 0 ok / 1 setup failed
; ---------------------------------------------------------------------------
miner_run PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48
    lea rcx, str_start
    call print_line
    call net_startup
    test eax, eax
    jz  mr_wsa
    call job_init
    call share_init
    mov dword ptr [g_running], 1
    ; thread count (needed for the memory budget)
    call cpu_count
    cmp eax, 1
    jge mr_t1
    mov eax, 1
mr_t1:
    cmp eax, 64
    jle mr_t2
    mov eax, 64
mr_t2:
    mov dword ptr [g_tcount], eax
    ; budget = dataset 2181038016 + cache 268501840 + tcount*(block+vm)
    mov ecx, eax
    imul rax, 2101512                  ; 2101000 (machine) + 512 (block)
    mov r11, 2181038016                ; dataset (imm64, >2^31 cannot be add-imm32)
    add rax, r11
    add rax, 268501840
    mov r11, 4294967296                ; 4 GiB hard cap
    cmp rax, r11
    ja  mr_budgetfail
    mov r12, rax
    shr rax, 20                        ; MB
    lea rdi, statbuf
    lea rcx, st_mem1
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rax, r12
    shr rax, 20
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    lea rcx, st_mem2
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov byte ptr [rdi], 0
    lea rcx, statbuf
    call print_line
    call randomx_alloc_cache
    test rax, rax
    jz  mr_nomem
    mov qword ptr [g_cache], rax
    call randomx_alloc_dataset
    test rax, rax
    jz  mr_nomem
    mov qword ptr [g_dataset], rax
    mov rcx, rax
    call randomx_get_dataset_memory
    mov qword ptr [g_dsmem], rax
    ; worker blocks
    mov ecx, dword ptr [g_tcount]
    shl ecx, 9                          ; *512
    call mem_alloc
    test rax, rax
    jz  mr_nomem
    mov qword ptr [g_workers], rax
    ; zero + init blocks
    mov rdi, rax
    mov eax, dword ptr [g_tcount]
    shl eax, 9
    shr eax, 3
    mov ecx, eax
    xor eax, eax
    rep stosq
    xor ebx, ebx
mr_blk:
    cmp ebx, dword ptr [g_tcount]
    jae mr_threads
    mov eax, ebx
    shl eax, 9
    mov rdi, qword ptr [g_workers]
    add rdi, rax
    mov dword ptr [rdi+WB_IDX], ebx
    mov rax, qword ptr [g_dsmem]
    mov qword ptr [rdi+WB_DSQ], rax
    inc ebx
    jmp mr_blk
mr_threads:
    xor ebx, ebx
    lea r15, g_whandles
mr_create:
    cmp ebx, dword ptr [g_tcount]
    jae mr_net
    mov eax, ebx
    shl eax, 9
    mov rdx, qword ptr [g_workers]
    add rdx, rax
    lea rcx, worker_proc
    call thread_create
    mov qword ptr [r15+rbx*8], rax
    inc ebx
    jmp mr_create
mr_net:
    lea rcx, net_thread
    xor edx, edx
    call thread_create
    mov qword ptr [g_neth], rax
    lea rcx, ctrl_handler
    mov edx, 1
    call SetConsoleCtrlHandler
mr_stats:
    xor r13, r13                        ; last hash total
mr_loop:
    mov ecx, 5000
    call Sleep
    cmp dword ptr [g_running], 0
    je  mr_quit
    cmp dword ptr [g_init_busy], 0
    je  mr_rate
    ; during dataset init show progress percent instead of hashrate
    lea rdi, statbuf
    lea rcx, st_initp
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rax, qword ptr [g_init_progress]
    xor edx, edx
    mov rcx, 340787                     ; ~100 / 34078719
    div rcx
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    mov byte ptr [rdi], '%'
    inc rdi
    mov byte ptr [rdi], 0
    lea rcx, statbuf
    call print_line
    mov r13, qword ptr [g_hashes]       ; avoid rate spike after init
    jmp mr_loop
mr_rate:
    lea rdi, statbuf
    lea rcx, st_hr1
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov r14, qword ptr [g_hashes]
    mov rax, r14
    sub rax, r13
    mov r13, r14
    xor edx, edx
    mov rcx, 5
    div rcx
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    lea rcx, st_hr2
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rax, qword ptr [g_shares]
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    lea rcx, st_hr3
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rax, qword ptr [g_acc]
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    lea rcx, st_hr4
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rax, qword ptr [g_rej]
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    lea rcx, st_hr5
    mov rdx, rdi
    call app_cstr
    add rdi, rax
    mov rax, qword ptr [g_dropped]
    mov rcx, rdi
    call fmt_u64
    add rdi, rax
    mov byte ptr [rdi], 0
    lea rcx, statbuf
    call print_line
    jmp mr_loop
mr_quit:
    mov dword ptr [g_running], 0
    mov rcx, qword ptr [g_neth]
    test rcx, rcx
    jz  mr_join
    mov edx, 10000
    call WaitForSingleObject
mr_join:
    xor ebx, ebx
    lea r15, g_whandles
mr_jl:
    cmp ebx, dword ptr [g_tcount]
    jae mr_ok
    mov rcx, qword ptr [r15+rbx*8]
    test rcx, rcx
    jz  mr_jnext
    mov edx, 5000
    call WaitForSingleObject
mr_jnext:
    inc ebx
    jmp mr_jl
mr_ok:
    lea rcx, str_stop
    call print_line
    xor eax, eax
    jmp mr_out
mr_nomem:
    lea rcx, str_nomem
    call print_line
    mov eax, 1
    jmp mr_out
mr_wsa:
    lea rcx, str_wsa
    call print_line
    mov eax, 1
    jmp mr_out
mr_budgetfail:
    lea rcx, str_budget
    call print_line
    mov eax, 1
mr_out:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
miner_run ENDP

END
