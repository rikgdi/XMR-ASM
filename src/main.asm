; XMRASM : entry point and top-level orchestration
; Windows x86-64, MASM (ml64)

option casemap:none

EXTERNDEF ExitProcess:PROC
EXTERNDEF console_init:PROC
EXTERNDEF print_line:PROC
EXTERNDEF run_self_tests:PROC
EXTERNDEF miner_run:PROC

.data
banner     db "XMRASM starting",0
str_notest db "tests failed; mining disabled",0

.code

main PROC
    and rsp, -16
    push rbx
    sub rsp, 40                         ; F=40 keeps rsp%16==0 before calls (1 push)
    call console_init
    lea rcx, banner
    call print_line
    call run_self_tests
    mov ebx, eax                        ; failure count
    test eax, eax
    jz  m_run
    lea rcx, str_notest
    call print_line
    mov ecx, ebx
    call ExitProcess
m_run:
    call miner_run
    xor ecx, ecx
    call ExitProcess
main ENDP

END
