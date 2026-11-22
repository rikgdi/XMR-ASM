; XMRASM : Winsock TCP helpers (blocking sockets + select)
; All functions use the Microsoft x64 calling convention.

option casemap:none

PUBLIC net_startup, net_connect, net_send_all, net_wait_read, net_recv, net_close

EXTERNDEF WSAStartup:PROC
EXTERNDEF getaddrinfo:PROC
EXTERNDEF freeaddrinfo:PROC
EXTERNDEF socket:PROC
EXTERNDEF connect:PROC
EXTERNDEF send:PROC
EXTERNDEF recv:PROC
EXTERNDEF select:PROC
EXTERNDEF closesocket:PROC
EXTERNDEF shutdown:PROC

SOCK_STREAM   EQU 1
IPPROTO_TCP   EQU 6
SD_BOTH       EQU 2
SOCKET_ERROR  EQU -1

.data?
wsa_data  db 408 dup(?)
ga_res    dq ?
ga_hints  db 48 dup(?)
tv_sel    db 16 dup(?)
fd_sel    db 64 dup(?)

.code

; ---------------------------------------------------------------------------
; net_startup -> rax = 1 ok / 0 fail
; ---------------------------------------------------------------------------
net_startup PROC
    sub rsp, 40
    mov ecx, 202h                      ; MAKEWORD(2,2)
    lea rdx, wsa_data
    call WSAStartup
    test eax, eax
    setz al
    movzx eax, al
    add rsp, 40
    ret
net_startup ENDP

; ---------------------------------------------------------------------------
; net_connect (rcx=host, rdx=port string) -> rax = socket | -1
; ---------------------------------------------------------------------------
net_connect PROC
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 40
    mov r12, rcx                        ; host
    mov r13, rdx                        ; port str
    lea rcx, ga_hints
    xor eax, eax
    mov qword ptr [rcx], rax
    mov qword ptr [rcx+8], rax
    mov qword ptr [rcx+16], rax
    mov qword ptr [rcx+24], rax
    mov qword ptr [rcx+32], rax
    mov qword ptr [rcx+40], rax
    mov dword ptr [rcx+8], SOCK_STREAM
    mov dword ptr [rcx+12], IPPROTO_TCP
    mov qword ptr [ga_res], 0
    mov rcx, r12
    mov rdx, r13
    lea r8, ga_hints
    lea r9, ga_res
    call getaddrinfo
    test eax, eax
    jnz nc_fail
    mov rbx, qword ptr [ga_res]
nc_loop:
    test rbx, rbx
    jz  nc_fail
    mov ecx, dword ptr [rbx+4]          ; ai_family
    mov edx, dword ptr [rbx+8]          ; ai_socktype
    mov r8d, dword ptr [rbx+12]         ; ai_protocol
    call socket
    cmp rax, -1
    je  nc_next
    mov r14, rax
    mov rcx, r14
    mov rdx, qword ptr [rbx+32]         ; ai_addr
    mov r8, qword ptr [rbx+16]          ; ai_addrlen
    call connect
    test eax, eax
    jz  nc_ok
    mov rcx, r14
    call closesocket
nc_next:
    mov rbx, qword ptr [rbx+40]         ; ai_next
    jmp nc_loop
nc_ok:
    mov rcx, qword ptr [ga_res]
    call freeaddrinfo
    mov rax, r14
    jmp nc_out
nc_fail:
    mov rax, -1
nc_out:
    add rsp, 40
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
net_connect ENDP

; ---------------------------------------------------------------------------
; net_send_all (rcx=sock, rdx=buf, r8=len) -> rax = 1 ok / 0 fail
; ---------------------------------------------------------------------------
net_send_all PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    mov rbx, rcx                        ; sock
    mov rsi, rdx                        ; ptr
    mov rdi, r8                         ; remaining
sa_loop:
    test rdi, rdi
    jz  sa_ok
    mov rcx, rbx
    mov rdx, rsi
    mov r8, rdi
    xor r9d, r9d
    call send
    cmp rax, 1
    jl  sa_fail
    add rsi, rax
    sub rdi, rax
    jmp sa_loop
sa_ok:
    mov eax, 1
    jmp sa_out
sa_fail:
    xor eax, eax
sa_out:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret
net_send_all ENDP

; ---------------------------------------------------------------------------
; net_wait_read (ecx=sock, edx=timeout ms) -> rax = 1 readable / 0 timeout
; ---------------------------------------------------------------------------
net_wait_read PROC
    push rbx
    sub rsp, 48
    mov ebx, ecx
    lea rcx, fd_sel
    xor eax, eax
    mov qword ptr [rcx], rax
    mov qword ptr [rcx+8], rax
    mov dword ptr [rcx], 1              ; fd_count
    mov dword ptr [rcx+8], ebx          ; fd array[0]
    mov eax, edx
    xor edx, edx
    mov r8d, 1000
    div r8d                             ; eax = sec, edx = msec rem
    lea rcx, tv_sel
    mov dword ptr [rcx], eax
    imul edx, edx, 1000
    mov dword ptr [rcx+4], edx
    xor ecx, ecx                        ; nfds
    lea rdx, fd_sel
    xor r8, r8
    xor r9, r9
    lea rax, tv_sel
    mov qword ptr [rsp+32], rax
    call select
    test eax, eax
    setg al
    movzx eax, al
    add rsp, 48
    pop rbx
    ret
net_wait_read ENDP

; ---------------------------------------------------------------------------
; net_recv (rcx=sock, rdx=buf, r8=maxlen) -> rax = n>0 | 0 closed | -1 error
; ---------------------------------------------------------------------------
net_recv PROC
    sub rsp, 40
    xor r9d, r9d                        ; flags
    call recv
    add rsp, 40
    ret
net_recv ENDP

; ---------------------------------------------------------------------------
; net_close (rcx=sock)
; ---------------------------------------------------------------------------
net_close PROC
    push rbx
    sub rsp, 48
    mov rbx, rcx
    cmp rbx, -1
    je  nc_done
    mov rcx, rbx
    mov edx, SD_BOTH
    call shutdown
    mov rcx, rbx
    call closesocket
nc_done:
    add rsp, 48
    pop rbx
    ret
net_close ENDP

END
