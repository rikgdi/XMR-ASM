; XMRASM : memory allocation helpers (VirtualAlloc wrappers)
;
; Exports:
;   mem_alloc             (rcx=size)             -> rax ptr or 0
;   mem_free              (rcx=ptr)              -> rax BOOL
;   mem_alloc_large       (rcx=size)             -> rax ptr or 0
;   mem_free_large        (rcx=ptr)              -> rax BOOL
;   mem_enable_large_pages()                     -> rax 1/0
;   mem_large_page_size   ()                     -> rax bytes
;
; mem_alloc_large requires a size that is a multiple of the large page
; size and mem_enable_large_pages() to have succeeded; returns 0 on
; failure (caller falls back to mem_alloc).

option casemap:none

PUBLIC mem_alloc, mem_free, mem_alloc_large, mem_free_large, \
       mem_enable_large_pages, mem_large_page_size

EXTERNDEF VirtualAlloc:PROC
EXTERNDEF VirtualFree:PROC
EXTERNDEF GetLargePageMinimum:PROC
EXTERNDEF GetCurrentProcess:PROC
EXTERNDEF CloseHandle:PROC
EXTERNDEF GetLastError:PROC
EXTERNDEF SetLastError:PROC
EXTERNDEF OpenProcessToken:PROC
EXTERNDEF LookupPrivilegeValueA:PROC
EXTERNDEF AdjustTokenPrivileges:PROC

MEM_COMMIT           EQU 1000h
MEM_RESERVE          EQU 2000h
MEM_RELEASE          EQU 8000h
MEM_LARGE_PAGES      EQU 20000000h
PAGE_READWRITE       EQU 4
TOKEN_ADJUST_PRIV    EQU 20h
TOKEN_QUERY          EQU 8
SE_PRIVILEGE_ENABLED EQU 2
ERROR_SUCCESS        EQU 0

.data
se_lock_name db "SeLockMemoryPrivilege",0

.code

; ---------------------------------------------------------------------------
; mem_alloc (rcx=size) -> rax ptr or 0
; ---------------------------------------------------------------------------
mem_alloc PROC
    sub rsp, 40
    mov rdx, rcx                    ; dwSize
    xor ecx, ecx                    ; lpAddress = NULL
    mov r8d, MEM_RESERVE or MEM_COMMIT
    mov r9d, PAGE_READWRITE
    call VirtualAlloc
    add rsp, 40
    ret
mem_alloc ENDP

; ---------------------------------------------------------------------------
; mem_free (rcx=ptr) -> rax BOOL
; ---------------------------------------------------------------------------
mem_free PROC
    sub rsp, 40
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
    add rsp, 40
    ret
mem_free ENDP

; ---------------------------------------------------------------------------
; mem_alloc_large (rcx=size) -> rax ptr or 0
; ---------------------------------------------------------------------------
mem_alloc_large PROC
    sub rsp, 40
    mov rdx, rcx                    ; dwSize
    xor ecx, ecx                    ; lpAddress = NULL
    mov r8d, MEM_RESERVE or MEM_COMMIT or MEM_LARGE_PAGES
    mov r9d, PAGE_READWRITE
    call VirtualAlloc
    add rsp, 40
    ret
mem_alloc_large ENDP

; ---------------------------------------------------------------------------
; mem_free_large (rcx=ptr) -> rax BOOL   (VirtualFree MEM_RELEASE)
; ---------------------------------------------------------------------------
mem_free_large PROC
    sub rsp, 40
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
    add rsp, 40
    ret
mem_free_large ENDP

; ---------------------------------------------------------------------------
; mem_large_page_size -> rax bytes (GetLargePageMinimum)
; ---------------------------------------------------------------------------
mem_large_page_size PROC
    sub rsp, 40
    call GetLargePageMinimum
    add rsp, 40
    ret
mem_large_page_size ENDP

; ---------------------------------------------------------------------------
; mem_enable_large_pages -> rax 1/0
;   OpenProcessToken(GetCurrentProcess(), ADJUST|QUERY), LookupPrivilegeValueA
;   ("SeLockMemoryPrivilege"), AdjustTokenPrivileges with
;   SE_PRIVILEGE_ENABLED, verify GetLastError()==ERROR_SUCCESS, close token.
;   Stack layout (after sub rsp,72):
;     [rsp+0..31]   shadow / stack args5-6 at +32,+40
;     [rsp+48..63]  TOKEN_PRIVILEGES (16): +0 count, +4 LUID, +12 attrs
;     [rsp+64..71]  token HANDLE
; ---------------------------------------------------------------------------
mem_enable_large_pages PROC
    sub rsp, 72
    mov ecx, -1                     ; GetCurrentProcess pseudo-handle
    call GetCurrentProcess
    mov rcx, rax
    mov edx, TOKEN_ADJUST_PRIV or TOKEN_QUERY
    lea r8, [rsp+64]                ; &token
    call OpenProcessToken
    test eax, eax
    jz mlp_fail
    lea rcx, se_lock_name
    xor edx, edx
    lea r8, [rsp+52]                ; &privileges.Privileges[0].Luid
    call LookupPrivilegeValueA
    test eax, eax
    jz mlp_close_fail
    mov dword ptr [rsp+48], 1       ; PrivilegeCount
    mov dword ptr [rsp+60], SE_PRIVILEGE_ENABLED
    xor ecx, ecx
    call SetLastError               ; SetLastError(ERROR_SUCCESS)
    mov rcx, [rsp+64]               ; token
    xor edx, edx                    ; DisableAllPrivileges = FALSE
    lea r8, [rsp+48]                ; &privileges
    mov r9d, 16                     ; sizeof(privileges)
    mov qword ptr [rsp+32], 0       ; lpPreviousState
    mov qword ptr [rsp+40], 0       ; pcbReturnSize
    call AdjustTokenPrivileges
    test eax, eax
    jz mlp_close_fail
    xor ecx, ecx
    call GetLastError
    test eax, eax
    jnz mlp_close_fail
    mov rcx, [rsp+64]
    call CloseHandle
    mov eax, 1
    jmp mlp_done
mlp_close_fail:
    mov rcx, [rsp+64]
    call CloseHandle
mlp_fail:
    xor eax, eax
mlp_done:
    add rsp, 72
    ret
mem_enable_large_pages ENDP

END
