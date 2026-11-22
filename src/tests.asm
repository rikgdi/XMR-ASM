; XMRASM : self tests
;
; run_self_tests PROC -> returns number of failures (rax)

option casemap:none

PUBLIC run_self_tests, check_match

EXTERNDEF print_cstr:PROC
EXTERNDEF print_line:PROC
EXTERNDEF fmt_hex_bytes:PROC
EXTERNDEF fmt_u64:PROC
EXTERNDEF hex_decode:PROC
EXTERNDEF blake2b:PROC
EXTERNDEF blake2b_init:PROC
EXTERNDEF blake2b_update:PROC
EXTERNDEF blake2b_final:PROC
EXTERNDEF blake2b_long:PROC
EXTERNDEF hashAes1Rx4:PROC
EXTERNDEF fillAes1Rx4:PROC
EXTERNDEF fillAes4Rx4:PROC
EXTERNDEF hashAndFillAes1Rx4:PROC
EXTERNDEF mem_alloc:PROC
EXTERNDEF mem_free:PROC
EXTERNDEF mem_alloc_large:PROC
EXTERNDEF mem_enable_large_pages:PROC
EXTERNDEF mem_large_page_size:PROC
EXTERNDEF cpu_detect:PROC
EXTERNDEF cpu_count:PROC
EXTERNDEF argon2_init_cache:PROC
EXTERNDEF b2gen_init:PROC
EXTERNDEF generateSuperscalar:PROC
EXTERNDEF randomx_alloc_cache:PROC
EXTERNDEF randomx_free_cache:PROC
EXTERNDEF randomx_init_cache:PROC
EXTERNDEF cache_init_programs:PROC
EXTERNDEF randomx_alloc_dataset:PROC
EXTERNDEF randomx_free_dataset:PROC
EXTERNDEF randomx_init_dataset:PROC
EXTERNDEF randomx_get_dataset_memory:PROC
EXTERNDEF jit_create:PROC
EXTERNDEF jit_destroy:PROC
EXTERNDEF jit_set_flags:PROC
EXTERNDEF jit_generate_program:PROC
EXTERNDEF jit_get_code:PROC
EXTERNDEF jit_get_codepos:PROC
EXTERNDEF randomx_create_vm:PROC
EXTERNDEF randomx_destroy_vm:PROC
EXTERNDEF randomx_calculate_hash:PROC

.data
tests_hdr  db "self tests:",0
pass_tag   db "  [PASS] ",0
fail_tag   db "  [FAIL] ",0
got_tag    db "         got: ",0
exp_tag    db "         exp: ",0
fail_cnt   db " failure(s)",0

t1_name db "hex_decode",0
t1_hex  db "00ff10ab7f",0
t1_exp  db 00h,0ffh,10h,0abh,07fh

t2_name db "blake2b-512(abc)",0
t2_hex  db "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1", \
           "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",0
t2_in   db "abc",0

t3_name db "blake2b-512(empty)",0
t3_hex  db "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419", \
           "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",0

t4_name db "blake2b-256(abc)",0
t4_hex  db "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",0

t5_name db "hashAes1Rx4(64)",0
t5_hex  db "d433854075fb8b0cb2c975bd5b83199d1d17af7960c91f3abd60bb2e8623fdbc", \
           "706f4a2f190070157f67dc5a18b683bab642c3f13836253461e93f72ff02f7ff",0

t6_name db "hashAes1Rx4(128)",0
t6_hex  db "07bc7f53e4044d92a3af7c4bfd47975097dba82abdfc3f782dbba6cb538db10f", \
           "c6efc14e92a21781b5d1983aa0218fad6394d3cfab81d14ad69757b90907f87b",0

t7_name  db "fillAes1Rx4(64)",0
t7s_name db "fillAes1Rx4(64,state)",0
t7_hex   db "05e06396dfa80b8732fa9a6dca65a8ba544a0fdb4e6728cd1aa8c7ec4467751", \
            "605faa8a6b4ac28d9cd717d7c9864aaa7077b125cb4bfdc6c1b70ea990b9a60c2",0

t8_name db "fillAes1Rx4(rx-kat)",0
t8in_hex db "6c19536eb2de31b6c0065f7f116e86f960d8af0c57210a6584c3237b9d064dc7",0
t8_hex  db "fa89397dd6ca422513aeadba3f124b5540324c4ad4b6db434394307a17c833ab", \
           "a330406d942cc6cd1d2b92a617b1726c56e28c091f52d9d2eb2f527537f2752a",0

t9_name  db "fillAes1Rx4(128)",0
t9s_name db "fillAes1Rx4(128,state)",0
t9_hex   db "05e06396dfa80b8732fa9a6dca65a8ba544a0fdb4e6728cd1aa8c7ec4467751", \
            "605faa8a6b4ac28d9cd717d7c9864aaa7077b125cb4bfdc6c1b70ea990b9a60c2", \
            "b78ee7be2968ec42c110e22da17689ef528887c02ac476c378473278e3e24d45", \
            "266e78c2579cd811fc381f159c5524b01ee358fb143f032887985f2d09872254",0
t9s_hex  db "b78ee7be2968ec42c110e22da17689ef528887c02ac476c378473278e3e24d45", \
            "266e78c2579cd811fc381f159c5524b01ee358fb143f032887985f2d09872254",0

t10_name  db "fillAes4Rx4(64)",0
t10s_name db "fillAes4Rx4(64,state)",0
t10_hex   db "65089c9806b2a8b2776a10d2eeab9f30b1738b2e17653da0907d3836756ae79", \
             "b3b574f67b1a48e6ef12dddf8060a25cc4c797684c7cf48c319ddcf155fbfdac", \
             "b",0
t10s_hex  db "5b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6", \
             "fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c5176",0

t11_name db "fillAes4Rx4(128)",0
t11_hex  db "65089c9806b2a8b2776a10d2eeab9f30b1738b2e17653da0907d3836756ae79", \
           "b3b574f67b1a48e6ef12dddf8060a25cc4c797684c7cf48c319ddcf155fbfdac", \
           "b81d3341dee0e01527a9031c2d56b2ef298a06237b840ba2a1a5a87ae0f95818", \
           "6ca5d83d4e852f7e89c316fabaf5db35e31157d5836a5e2d35eb32d69188ce0a1",0

t12_name db "hashAndFill(512,hash)",0
t12b_name db "hashAndFill(512,fill)",0
t12c_name db "hashAndFill(512,sp0)",0
t12d_name db "hashAndFill(512,sp448)",0
t12_hex  db "6031116d5a989a01e37dd3e0a149f9b417ca35a51e9a341f9b94600543146c62", \
           "8e50acf65f6c05399a234eeeed4335784b13e6ddefc32e27609fa03ebf5e943b",0
t12b_hex db "46632ddca4412d94aba34b6b26f511da9d2aef5ae95967728e6e73ad5f7ff60e", \
           "fe90e5d3253c9c83b2218dda7b3b826469f1c16c2eb5bd8d9a33c27f4e4fa023",0
t12c_hex db "996c5fe31c7469270fcc77be9428b40eb147d2ccd48ba8822f5c98af7498ab22", \
           "25363add6939d51f77be461e872b10d15e7950891bed5e8e981281f53d2dcd26",0

t13_name  db "hashAndFill(8192,hash)",0
t13b_name db "hashAndFill(8192,fill)",0
t13c_name db "hashAndFill(8192,sp0)",0
t13d_name db "hashAndFill(8192,sp4096)",0
t13e_name db "hashAndFill(8192,sp8128)",0
t13_hex  db "50e7b59c94b8a0f11d399b280ebd0dabaa036df4ce28da81ff151d83d5e63881", \
           "55dfa0f8d8c5f009b59eb4d362b7e529392d36ed5e71ddbef55fbc7bcb973ba8",0
t13b_hex db "b02242054cdcbaee6b2641a996079fd599fad91b330f5bb98a42b33f81248f5e", \
           "adac5e9627502c3d05c6db1d69323e017e29eea51d3d04ef28def64bde26d85c",0
t13d_hex db "27158f39edcfedac6a9af7ebb8f24487b00167badf569f66b0f0a80998bebd3c", \
           "84493691124614b78926d1dc4d8bee1a0f20f4667968903b6d0c9c49b5cd3f76",0

m1_name db "mem_alloc/free",0
m2_name db "mem_alloc(large)",0
c1_name db "cpu_detect(aes)",0
c2_name db "cpu_count(>=1)",0
a2t_name db "argon2 cache KAT",0
a2_key   db "test key 000"

ss1_name db "superscalar x8 (instr)",0
ss2_name db "superscalar x8 (stats)",0
cpt_name db "cache programs (rcp)",0
cit_name db "cache init (full)",0
dst_name db "dataset items",0
dst_items dq 0, 65535, 16777216, 33554431
; dataset KAT (key "test key 000"): 4 items x 64 bytes
dst_kat db 0DBh,022h,0E2h,05Ah,0A8h,088h,005h,068h,0F4h,016h,0FFh,090h,03Dh,0C1h,0C9h,091h
        db 0A8h,0B4h,079h,014h,036h,058h,00Ch,02Ch,0B7h,078h,0EDh,06Ch,08Ch,0A3h,0F7h,026h
        db 055h,043h,037h,031h,02Bh,055h,04Dh,0DBh,0D1h,012h,0D2h,087h,0FEh,0D9h,07Dh,0FFh
        db 0B9h,06Eh,01Fh,0D4h,08Eh,00Eh,098h,036h,071h,0F2h,0D8h,02Ah,0E0h,058h,0F8h,07Fh
        db 0A0h,079h,03Ah,044h,04Ah,0F1h,0A4h,0DDh,0E5h,07Bh,002h,013h,0E6h,01Fh,0CDh,0EAh
        db 035h,023h,083h,0D2h,074h,0B3h,034h,0A3h,024h,0ECh,0A3h,0F0h,005h,00Ah,0D7h,038h
        db 028h,0C6h,08Bh,08Eh,0BCh,019h,06Eh,010h,011h,0C7h,0A2h,03Eh,063h,006h,0A7h,02Ah
        db 0CFh,077h,03Ah,0B8h,007h,0FFh,07Ch,0EEh,060h,0FCh,0C0h,053h,05Dh,066h,0E0h,089h
        db 0ABh,09Ah,032h,087h,097h,0C5h,0DDh,039h,0F8h,06Ch,0DCh,008h,06Fh,0A5h,070h,09Fh
        db 009h,0E9h,0A7h,0B6h,073h,0A2h,00Bh,0C0h,0CBh,01Eh,002h,0C7h,08Dh,0F2h,074h,086h
        db 021h,076h,0A3h,07Ch,06Ah,0A9h,019h,040h,08Dh,09Ch,00Eh,00Fh,066h,05Bh,030h,0E1h
        db 03Bh,079h,032h,0A1h,0C6h,0E8h,027h,054h,095h,0CFh,072h,001h,0BFh,017h,0D5h,0A0h
        db 03Ah,0BAh,0C2h,0E1h,05Bh,0D1h,0A1h,07Dh,0BCh,00Fh,06Eh,0B4h,0F5h,0C2h,027h,0C5h
        db 059h,068h,078h,023h,0B4h,0FCh,0ABh,018h,0C4h,040h,025h,0ECh,061h,0EBh,038h,0DCh
        db 0C0h,0A3h,066h,0B7h,005h,019h,0DAh,073h,06Bh,05Eh,0CEh,063h,077h,096h,0FEh,0C4h
        db 001h,091h,020h,091h,060h,047h,027h,028h,098h,0A7h,00Bh,051h,0FFh,0BEh,0EEh,0DBh
; cache programs KAT: u16 recipCount, u32 recip FNV, 8x u32 program FNV
cpt_kat db 0EFh,00h, 0F6h,0C9h,0B7h,0A7h
        db 051h,01Fh,00Eh,0BBh, 06Bh,0C6h,0B8h,09Eh
        db 0A1h,0E1h,08Ah,0C2h, 077h,058h,076h,0C8h
        db 039h,0ACh,080h,022h, 06Ah,0E2h,0C2h,0BEh
        db 088h,03Ah,074h,099h, 056h,02Ch,07Fh,009h
; per program: u16 LE size, u8 addr, u32 LE fnv (FNV-1a over instruction bytes)
ss1_kat db 0BFh,01h,04h, 0F1h,6Eh,28h,0BDh
        db 0B6h,01h,05h, 05Eh,72h,6Ah,0C9h
        db 0C1h,01h,04h, 009h,0DBh,11h,0B6h
        db 0BFh,01h,03h, 0F5h,0B2h,87h,9Dh
        db 0BCh,01h,04h, 045h,07h,01h,000h
        db 0C1h,01h,00h, 0DCh,0B8h,0F0h,0CBh
        db 0C4h,01h,05h, 065h,0DAh,37h,47h
        db 0B5h,01h,00h, 050h,082h,0D4h,0FEh
; per program: u16 mops, u16 codeSize, u16 cpuLatency, u8 asicLatency,
;             u16 mulCount, u8 decodeCycles  (10 bytes each)
ss2_kat db 018h,02h, 05Bh,09h, 0AEh,00h, 061h, 09Dh,00h, 09Ch
        db 01Fh,02h, 094h,09h, 0ABh,00h, 05Bh, 09Fh,00h, 09Fh
        db 015h,02h, 042h,09h, 0ADh,00h, 060h, 09Bh,00h, 099h
        db 016h,02h, 04Fh,09h, 0ADh,00h, 05Fh, 09Ch,00h, 09Ah
        db 01Ch,02h, 082h,09h, 0ADh,00h, 05Ah, 09Fh,00h, 09Eh
        db 015h,02h, 055h,09h, 0ADh,00h, 05Dh, 09Ch,00h, 09Bh
        db 012h,02h, 03Bh,09h, 0ADh,00h, 05Ch, 09Bh,00h, 099h
        db 015h,02h, 060h,09h, 0ADh,00h, 05Ch, 09Dh,00h, 09Ch

bl1_name db "blake2b_long(64,abc)",0
bl1_hex  db "f32577a3172f56657d531faaa43077bb8c9726ada7bb04dd337ec5a65454abff", \
           "241ad6b87a72440e5127c6f9caa70327f2a699096e52d163eb52d9cd99620593",0

bl2_name db "blake2b_long(100,abc)",0
bl2_hex  db "4c9ba23bcafae5e571a5d41673bb8084a4a1de2688416ed390f669d33d364f3d", \
           "4d9bfa7fe762680c6b2362711c4ce5b2c60ddcd14c1277ec1369c79f44c28966", \
           "98a2b0773a3ce2e410532fa7c72f0bb61ccca0c24c362f337555cbf2998f2d36", \
           "01be70d1",0

bl3_name  db "blake2b_long(1024,first)",0
bl3b_name db "blake2b_long(1024,last)",0
a2_salt   db "RandomX",03h
bl3_hex  db "6fd03830ada0526514e82233fc6a1dfec9eefbcc1a0e7c2dc1336f4ea4f038f", \
           "46fba1dede88e98d409f6bb3411b00cae7e74e4eb82d4797f8b37ff27f2bb7176",0
bl3b_hex db "663af1e19873ddb254eaf41206b9e1cbbc73fdf6d25810d57975abcc9627c950", \
           "70ed7c4c8b17d20e2cefeef4977846bed06bbe378f71d567eef15c3a799357e0",0

jk_name db "jit generate (16x fnv64)",0

vmh_name db "vm flow (abc,zero ds)",0
vmh_hex  db "bc81f678a04c5449674a65f512f758a6c9eba7e464642e5d138d9d39f60145a3",0
vmh_in   db "abc",0

.data?
tests_failed dd ?
vm_flags  dd ?
vmh_dsq   dq ?
vmh_ds    dq ?
vmh_vm    dq ?
jk_flags  dd ?
jit_pbuf  db 3200 dup(?)
jit_cfg   db 32 dup(?)
actual   db 128 dup(?)
expect   db 128 dup(?)
hexbuf   db 260 dup(?)
aes_in    db 256 dup(?)
aes_state db 64 dup(?)
aes_out   db 256 dup(?)
aes_fs    db 64 dup(?)
aes_hash  db 64 dup(?)
aes_sp    db 8192 dup(?)
b2blbuf   db 1024 dup(?)
ss_gen    db 72 dup(?)
ss_progs  db 33600 dup(?)
ss_actual db 56 dup(?)
ss_stats  db 80 dup(?)
cache_ptr dq ?

.code

; ---------------------------------------------------------------------------
; check_match (rcx=name, rdx=actual, r8=expected, r9=len)
;   prints result line; increments tests_failed on mismatch; on mismatch
;   prints got/exp hex lines.
; ---------------------------------------------------------------------------
check_match PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 64
    mov rbx, rcx
    mov [rsp+32], rdx
    mov [rsp+40], r8
    mov [rsp+48], r9
    mov rsi, rdx
    mov rdi, r8
    mov rcx, r9
    xor r10d, r10d
    test rcx, rcx
    jz cm_print
cm_loop:
    mov al, [rsi]
    cmp al, [rdi]
    jne cm_fail
    inc rsi
    inc rdi
    dec rcx
    jnz cm_loop
    jmp cm_print
cm_fail:
    mov r10d, 1
cm_print:
    test r10d, r10d
    jnz cm_bad
    lea rcx, pass_tag
    call print_cstr
    mov rcx, rbx
    call print_line
    jmp cm_done
cm_bad:
    inc dword ptr [tests_failed]
    lea rcx, fail_tag
    call print_cstr
    mov rcx, rbx
    call print_line
    lea rcx, got_tag
    call print_cstr
    mov rcx, [rsp+32]
    mov rdx, [rsp+48]
    lea r8, hexbuf
    call fmt_hex_bytes
    lea r11, hexbuf
    mov byte ptr [r11+rax], 0
    lea rcx, hexbuf
    call print_line
    lea rcx, exp_tag
    call print_cstr
    mov rcx, [rsp+40]
    mov rdx, [rsp+48]
    lea r8, hexbuf
    call fmt_hex_bytes
    lea r11, hexbuf
    mov byte ptr [r11+rax], 0
    lea rcx, hexbuf
    call print_line
cm_done:
    xor eax, eax
    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    ret
check_match ENDP

; ---------------------------------------------------------------------------
; fill_pattern (rcx=buf, rdx=len, r8=start, r9=add)
;   buf[i] = (start + i*add) mod 256
; ---------------------------------------------------------------------------
fill_pattern PROC
    mov rax, r8
    xor r10d, r10d
    test rdx, rdx
    jz fp_done
fp_loop:
    mov [rcx+r10], al
    add al, r9b
    inc r10
    cmp r10, rdx
    jb fp_loop
fp_done:
    ret
fill_pattern ENDP

; ---------------------------------------------------------------------------
; fnv32 (rcx=ptr, rdx=len) -> eax   (FNV-1a over bytes)
; ---------------------------------------------------------------------------
fnv32 PROC
    xor r10d, r10d
    mov eax, 811C9DC5h
fnv32_lp:
    cmp r10, rdx
    jae fnv32_end
    movzx r8d, byte ptr [rcx+r10]
    xor eax, r8d
    imul eax, 16777619
    inc r10
    jmp fnv32_lp
fnv32_end:
    ret
fnv32 ENDP

; ---------------------------------------------------------------------------
; run_self_tests -> rax = number of failures
; ---------------------------------------------------------------------------
run_self_tests PROC
    push r12
    push r13
    push r14
    sub rsp, 48
    mov dword ptr [tests_failed], 0

    lea rcx, tests_hdr
    call print_line

    ; ---- hex_decode ----
    lea rcx, t1_hex
    mov rdx, 10
    lea r8, actual
    call hex_decode
    lea rcx, t1_name
    lea rdx, actual
    lea r8, t1_exp
    mov r9, 5
    call check_match

    ; ---- blake2b-512("abc") ----
    lea rcx, t2_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, actual
    mov rdx, 64
    lea r8, t2_in
    mov r9, 3
    call blake2b
    lea rcx, t2_name
    lea rdx, actual
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- blake2b-512("") ----
    lea rcx, t3_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, actual
    mov rdx, 64
    lea r8, t2_in                 ; dummy pointer, length 0
    xor r9d, r9d
    call blake2b
    lea rcx, t3_name
    lea rdx, actual
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- blake2b-256("abc") ----
    lea rcx, t4_hex
    mov rdx, 64
    lea r8, expect
    call hex_decode
    lea rcx, actual
    mov rdx, 32
    lea r8, t2_in
    mov r9, 3
    call blake2b
    lea rcx, t4_name
    lea rdx, actual
    lea r8, expect
    mov r9, 32
    call check_match

    ; ---- blake2b_long(64, "abc") ----
    lea rcx, bl1_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, b2blbuf
    mov rdx, 64
    lea r8, t2_in
    mov r9, 3
    call blake2b_long
    lea rcx, bl1_name
    lea rdx, b2blbuf
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- blake2b_long(100, "abc") ----
    lea rcx, bl2_hex
    mov rdx, 200
    lea r8, expect
    call hex_decode
    lea rcx, b2blbuf
    mov rdx, 100
    lea r8, t2_in
    mov r9, 3
    call blake2b_long
    lea rcx, bl2_name
    lea rdx, b2blbuf
    lea r8, expect
    mov r9, 100
    call check_match

    ; ---- blake2b_long(1024, "RandomX\x03") : first 64 ----
    lea rcx, bl3_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, b2blbuf
    mov rdx, 1024
    lea r8, a2_salt
    mov r9, 8
    call blake2b_long
    lea rcx, bl3_name
    lea rdx, b2blbuf
    lea r8, expect
    mov r9, 64
    call check_match
    ; ---- last 64 (offset 960) ----
    lea rcx, bl3b_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, bl3b_name
    lea rdx, b2blbuf
    add rdx, 960
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- hashAes1Rx4(64) ----
    lea rcx, aes_in
    mov rdx, 256
    mov r8, 41
    mov r9, 73
    call fill_pattern
    lea rcx, aes_in
    mov rdx, 64
    lea r8, aes_hash
    call hashAes1Rx4
    lea rcx, t5_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t5_name
    lea rdx, aes_hash
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- hashAes1Rx4(128) ----
    lea rcx, aes_in
    mov rdx, 128
    lea r8, aes_hash
    call hashAes1Rx4
    lea rcx, t6_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t6_name
    lea rdx, aes_hash
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- fillAes1Rx4(64, separate buffer) ----
    lea rcx, aes_state
    mov rdx, 64
    mov r8, 91
    mov r9, 37
    call fill_pattern
    lea rcx, aes_state
    mov rdx, 64
    lea r8, aes_out
    call fillAes1Rx4
    lea rcx, t7_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t7_name
    lea rdx, aes_out
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t7s_name
    lea rdx, aes_state
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- fillAes1Rx4 RandomX tests.cpp vector (buffer == state) ----
    lea rcx, aes_state
    mov rdx, 64
    xor r8d, r8d
    xor r9d, r9d
    call fill_pattern
    lea rcx, t8in_hex
    mov rdx, 64
    lea r8, aes_state
    call hex_decode
    lea rcx, aes_state
    mov rdx, 64
    lea r8, aes_state
    call fillAes1Rx4
    lea rcx, t8_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t8_name
    lea rdx, aes_state
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- fillAes1Rx4(128) ----
    lea rcx, aes_state
    mov rdx, 64
    mov r8, 91
    mov r9, 37
    call fill_pattern
    lea rcx, aes_state
    mov rdx, 128
    lea r8, aes_out
    call fillAes1Rx4
    lea rcx, t9_hex
    mov rdx, 256
    lea r8, expect
    call hex_decode
    lea rcx, t9_name
    lea rdx, aes_out
    lea r8, expect
    mov r9, 128
    call check_match
    lea rcx, t9s_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t9s_name
    lea rdx, aes_state
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- fillAes4Rx4(64) ----
    lea rcx, aes_state
    mov rdx, 64
    mov r8, 91
    mov r9, 37
    call fill_pattern
    lea rcx, aes_state
    mov rdx, 64
    lea r8, aes_out
    call fillAes4Rx4
    lea rcx, t10_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t10_name
    lea rdx, aes_out
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t10s_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t10s_name
    lea rdx, aes_state
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- fillAes4Rx4(128) ----
    lea rcx, aes_state
    mov rdx, 64
    mov r8, 91
    mov r9, 37
    call fill_pattern
    lea rcx, aes_state
    mov rdx, 128
    lea r8, aes_out
    call fillAes4Rx4
    lea rcx, t11_hex
    mov rdx, 256
    lea r8, expect
    call hex_decode
    lea rcx, t11_name
    lea rdx, aes_out
    lea r8, expect
    mov r9, 128
    call check_match

    ; ---- hashAndFillAes1Rx4(512) ----
    lea rcx, aes_sp
    mov rdx, 512
    mov r8, 7
    mov r9, 13
    call fill_pattern
    lea rcx, aes_fs
    mov rdx, 64
    mov r8, 55
    mov r9, 19
    call fill_pattern
    lea rcx, aes_sp
    mov rdx, 512
    lea r8, aes_hash
    lea r9, aes_fs
    call hashAndFillAes1Rx4
    lea rcx, t12_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t12_name
    lea rdx, aes_hash
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t12b_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t12b_name
    lea rdx, aes_fs
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t12d_name
    lea rdx, aes_sp
    add rdx, 448
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t12c_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t12c_name
    lea rdx, aes_sp
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- hashAndFillAes1Rx4(8192) ----
    lea rcx, aes_sp
    mov rdx, 8192
    mov r8, 7
    mov r9, 13
    call fill_pattern
    lea rcx, aes_fs
    mov rdx, 64
    mov r8, 55
    mov r9, 19
    call fill_pattern
    lea rcx, aes_sp
    mov rdx, 8192
    lea r8, aes_hash
    lea r9, aes_fs
    call hashAndFillAes1Rx4
    lea rcx, t13_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t13_name
    lea rdx, aes_hash
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t13b_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t13b_name
    lea rdx, aes_fs
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t13e_name
    lea rdx, aes_sp
    add rdx, 8128
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t12c_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t13c_name
    lea rdx, aes_sp
    lea r8, expect
    mov r9, 64
    call check_match
    lea rcx, t13d_hex
    mov rdx, 128
    lea r8, expect
    call hex_decode
    lea rcx, t13d_name
    lea rdx, aes_sp
    add rdx, 4096
    lea r8, expect
    mov r9, 64
    call check_match

    ; ---- mem_alloc/free ----
    mov ecx, 65536
    call mem_alloc
    mov r12, rax
    test r12, r12
    jz m1_zero
    mov byte ptr [r12], 5Ah
    cmp byte ptr [r12], 5Ah
    jne m1_bad
    mov rcx, r12
    call mem_free
    test eax, eax
    jz m1_zero
    mov byte ptr [actual], 1
    jmp m1_check
m1_bad:
    mov rcx, r12
    call mem_free
    mov byte ptr [actual], 2
    jmp m1_check
m1_zero:
    mov byte ptr [actual], 0
m1_check:
    mov byte ptr [expect], 1
    lea rcx, m1_name
    lea rdx, actual
    lea r8, expect
    mov r9, 1
    call check_match

    ; ---- mem_alloc(large): privilege + large-page attempt, fallback ----
    call mem_enable_large_pages
    call mem_large_page_size
    test rax, rax
    jnz m2_have_size
    mov eax, 65536
m2_have_size:
    mov r12, rax                    ; size (>= large page min)
    mov rcx, r12
    call mem_alloc_large
    test rax, rax
    jnz m2_got
    mov rcx, r12
    call mem_alloc
    test rax, rax
    jz m2_zero
m2_got:
    mov byte ptr [rax], 77h
    cmp byte ptr [rax], 77h
    jne m2_bad
    mov rcx, rax
    call mem_free
    test eax, eax
    jz m2_zero
    mov byte ptr [actual], 1
    jmp m2_check
m2_bad:
    mov byte ptr [actual], 2
    jmp m2_check
m2_zero:
    mov byte ptr [actual], 0
m2_check:
    mov byte ptr [expect], 1
    lea rcx, m2_name
    lea rdx, actual
    lea r8, expect
    mov r9, 1
    call check_match

    ; ---- cpu_detect: AES-NI bit (RandomX requirement) ----
    call cpu_detect
    and eax, 2
    mov byte ptr [actual], al
    mov byte ptr [expect], 2
    lea rcx, c1_name
    lea rdx, actual
    lea r8, expect
    mov r9, 1
    call check_match

    ; ---- cpu_count: >= 1 ----
    call cpu_count
    test eax, eax
    setnz al
    mov byte ptr [actual], al
    mov byte ptr [expect], 1
    lea rcx, c2_name
    lea rdx, actual
    lea r8, expect
    mov r9, 1
    call check_match

    ; ---- superscalar x8 (seed "test key 000", nonce 0) ----
    lea rcx, ss_gen
    lea rdx, a2_key
    mov r8, 12
    xor r9d, r9d
    call b2gen_init
    xor r12d, r12d
ss_gen_lp:
    imul rax, r12, 4200
    lea r13, ss_progs
    add r13, rax                    ; prog
    mov rcx, r13
    lea rdx, ss_gen
    call generateSuperscalar
    ; actual instruction entry (7 bytes)
    imul rax, r12, 7
    lea r14, ss_actual
    add r14, rax
    mov ax, word ptr [r13+4096]
    mov word ptr [r14], ax          ; size
    mov al, byte ptr [r13+4100]
    mov byte ptr [r14+2], al        ; addrReg
    ; FNV-1a over instruction bytes
    movzx r9d, word ptr [r13+4096]
    shl r9d, 3                      ; size * 8
    xor r8d, r8d
    mov edx, 811C9DC5h
ss_fnv:
    cmp r8, r9
    jae ss_fnv_done
    movzx eax, byte ptr [r13+r8]
    xor eax, edx
    imul eax, 16777619
    mov edx, eax
    inc r8
    jmp ss_fnv
ss_fnv_done:
    mov dword ptr [r14+3], edx      ; fnv (LE)
    ; actual stats entry (10 bytes)
    imul rax, r12, 10
    lea r14, ss_stats
    add r14, rax
    mov ax, word ptr [r13+4180]
    mov word ptr [r14], ax          ; macroOps
    mov ax, word ptr [r13+4176]
    mov word ptr [r14+2], ax        ; codeSize
    mov ax, word ptr [r13+4168]
    mov word ptr [r14+4], ax        ; cpuLatency
    mov al, byte ptr [r13+4172]
    mov byte ptr [r14+6], al        ; asicLatency
    mov ax, word ptr [r13+4188]
    mov word ptr [r14+7], ax        ; mulCount
    mov al, byte ptr [r13+4184]
    mov byte ptr [r14+9], al        ; decodeCycles
    inc r12
    cmp r12, 8
    jb  ss_gen_lp
    lea rcx, ss1_name
    lea rdx, ss_actual
    lea r8, ss1_kat
    mov r9, 56
    call check_match
    lea rcx, ss2_name
    lea rdx, ss_stats
    lea r8, ss2_kat
    mov r9, 80
    call check_match

    ; ---- argon2 cache KAT ("test key 000", 256 MiB) ----
    ; expected qwords: [mem+0]=191E0E1D23C02186h, [mem+12547304]=0F1B62FE6210BF8B1h,
    ;                  [mem+268435448]=1F47F056D05CD99Bh
    mov ecx, 268435456
    call mem_alloc
    mov qword ptr [rsp+32], rax
    test rax, rax
    jz a2t_zero
    mov rcx, rax
    lea rdx, a2_key
    mov r8, 12
    call argon2_init_cache
    mov byte ptr [actual], 0
    mov rax, 191E0E1D23C02186h
    mov rcx, qword ptr [rsp+32]
    cmp qword ptr [rcx], rax
    jne a2t_n1
    or byte ptr [actual], 1
a2t_n1:
    mov rax, 0F1B62FE6210BF8B1h
    mov rcx, qword ptr [rsp+32]
    cmp qword ptr [rcx+12547304], rax
    jne a2t_n2
    or byte ptr [actual], 2
a2t_n2:
    mov rax, 1F47F056D05CD99Bh
    mov rcx, qword ptr [rsp+32]
    cmp qword ptr [rcx+268435448], rax
    jne a2t_n3
    or byte ptr [actual], 4
a2t_n3:
    mov rcx, qword ptr [rsp+32]
    call mem_free
    jmp a2t_check
a2t_zero:
    mov byte ptr [actual], 0
a2t_check:
    mov byte ptr [expect], 7
    lea rcx, a2t_name
    lea rdx, actual
    lea r8, expect
    mov r9, 1
    call check_match

    ; ---- cache programs (rcp) : alloc + 8 programs + IMUL_RCP replacement ----
    ; NOTE: cache layout constants must match src\cache.asm
    call randomx_alloc_cache
    test rax, rax
    jz  cprog_fail
    mov qword ptr [cache_ptr], rax
    mov rcx, rax
    lea rdx, a2_key
    mov r8, 12
    call cache_init_programs
    mov r12, qword ptr [cache_ptr]
    lea r11, actual
    mov ax, word ptr [r12+66376]    ; recipCount
    mov word ptr [r11], ax
    lea rcx, [r12+33608]            ; recipCache
    movzx rdx, word ptr [r12+66376]
    shl rdx, 3
    call fnv32
    lea r11, actual
    mov dword ptr [r11+2], eax      ; recip FNV
    xor r13d, r13d
    mov r14d, 6
cprog_plp:
    imul rax, r13, 4200
    lea rcx, [r12+rax+8]            ; &programs[i]
    movzx rdx, word ptr [rcx+4096]
    shl rdx, 3
    call fnv32
    lea r11, actual
    mov dword ptr [r11+r14], eax    ; program FNV
    add r14d, 4
    inc r13d
    cmp r13d, 8
    jb  cprog_plp
    lea rcx, cpt_name
    lea rdx, actual
    lea r8, cpt_kat
    mov r9, 38
    call check_match
    mov rcx, qword ptr [cache_ptr]
    call randomx_free_cache
    jmp cprog_done
cprog_fail:
    lea r11, actual
    xor eax, eax
    mov ecx, 38
cprog_fz:
    mov byte ptr [r11], al
    inc r11
    dec ecx
    jnz cprog_fz
    lea rcx, cpt_name
    lea rdx, actual
    lea r8, cpt_kat
    mov r9, 38
    call check_match
cprog_done:

    ; ---- cache init (full) : argon2 fill + programs in one call ----
    call randomx_alloc_cache
    test rax, rax
    jz  cinit_fail
    mov qword ptr [cache_ptr], rax
    mov rcx, rax
    lea rdx, a2_key
    mov r8, 12
    call randomx_init_cache
    mov r12, qword ptr [cache_ptr]
    mov r11, qword ptr [r12]        ; memory
    xor r13d, r13d
    mov rax, 191E0E1D23C02186h
    cmp qword ptr [r11], rax
    jne cinit_s1
    or  r13d, 1
cinit_s1:
    mov rax, 0F1B62FE6210BF8B1h
    cmp qword ptr [r11+12547304], rax
    jne cinit_s2
    or  r13d, 2
cinit_s2:
    mov rax, 1F47F056D05CD99Bh
    cmp qword ptr [r11+268435448], rax
    jne cinit_s3
    or  r13d, 4
cinit_s3:
    cmp word ptr [r12+66376], 239
    jne cinit_s4
    or  r13d, 8
cinit_s4:
    lea rcx, [r12+33608]
    movzx rdx, word ptr [r12+66376]
    shl rdx, 3
    call fnv32
    cmp eax, 0A7B7C9F6h
    jne cinit_s5
    or  r13d, 16
cinit_s5:
    cmp word ptr [r12+4104], 447    ; programs[0].size
    jne cinit_s6
    or  r13d, 32
cinit_s6:
    lea r11, actual
    mov byte ptr [r11], r13b
    mov byte ptr [expect], 3Fh
    lea rcx, cit_name
    lea rdx, actual
    lea r8, expect
    mov r9, 1
    call check_match
    mov rcx, qword ptr [cache_ptr]
    call randomx_free_cache
    jmp cinit_done
cinit_fail:
    lea r11, actual
    mov byte ptr [r11], 0
    mov byte ptr [expect], 3Fh
    lea rcx, cit_name
    lea rdx, actual
    lea r8, expect
    mov r9, 1
    call check_match
cinit_done:

    ; ---- dataset items (x4) ----
    call randomx_alloc_cache
    test rax, rax
    jz  dst_fail
    mov r12, rax
    mov rcx, r12
    lea rdx, a2_key
    mov r8, 12
    call randomx_init_cache
    call randomx_alloc_dataset
    test rax, rax
    jz  dst_cachefail
    mov r13, rax
    mov rcx, r13
    call randomx_get_dataset_memory
    test rax, rax
    jz  dst_dsnull
    mov qword ptr [rsp+40], rax
    mov byte ptr [rsp+32], 0
    xor r14d, r14d
dst_loop:
    cmp r14d, 4
    jae dst_cmp
    lea r11, dst_items
    mov rcx, r13
    mov rdx, r12
    mov r8, [r11+r14*8]
    mov r9, 1
    call randomx_init_dataset
    mov rax, [rsp+40]
    lea r11, dst_items
    mov r11, [r11+r14*8]
    shl r11, 6
    add rax, r11                    ; src = memory + item*64
    lea rdx, dst_kat
    imul r11, r14, 64
    add rdx, r11                    ; kats + i*64
    mov rcx, [rax]
    cmp rcx, [rdx]
    jne dst_next
    mov rcx, [rax+8]
    cmp rcx, [rdx+8]
    jne dst_next
    mov rcx, [rax+16]
    cmp rcx, [rdx+16]
    jne dst_next
    mov rcx, [rax+24]
    cmp rcx, [rdx+24]
    jne dst_next
    mov rcx, [rax+32]
    cmp rcx, [rdx+32]
    jne dst_next
    mov rcx, [rax+40]
    cmp rcx, [rdx+40]
    jne dst_next
    mov rcx, [rax+48]
    cmp rcx, [rdx+48]
    jne dst_next
    mov rcx, [rax+56]
    cmp rcx, [rdx+56]
    jne dst_next
    mov ecx, r14d
    mov eax, 1
    shl eax, cl
    or  byte ptr [rsp+32], al
dst_next:
    inc r14d
    jmp dst_loop
dst_cmp:
    or  byte ptr [rsp+32], 80h      ; reached = items computed
    mov rcx, r13
    call randomx_free_dataset
    mov rcx, r12
    call randomx_free_cache
    jmp dst_chk
dst_dsnull:
    mov rcx, r13
    call randomx_free_dataset
    mov rcx, r12
    call randomx_free_cache
    mov byte ptr [rsp+32], 0C0h
    jmp dst_chk
dst_cachefail:
    mov rcx, r12
    call randomx_free_cache
    mov byte ptr [rsp+32], 0B0h
    jmp dst_chk
dst_fail:
    mov byte ptr [rsp+32], 0A0h
dst_chk:
    lea r11, actual
    mov al, byte ptr [rsp+32]
    mov byte ptr [r11], al
    mov byte ptr [expect], 8Fh
    lea rcx, dst_name
    lea rdx, actual
    lea r8, expect
    mov r9, 1
    call check_match
dst_done:

    ; ---- jit generate (16 programs, FNV64 KAT) ----
    mov dword ptr [jk_flags], 0
    call jit_create
    test rax, rax
    jz  jk_chk
    mov r12, rax
    or  dword ptr [jk_flags], 1
    mov rcx, r12
    mov edx, 14
    call jit_set_flags
    lea r11, jit_cfg
    mov rax, 0123456789ABCDEFh
    mov qword ptr [r11], rax
    mov rax, 0FEDCBA0987654321h
    mov qword ptr [r11+8], rax
    mov dword ptr [r11+16], 1
    mov dword ptr [r11+20], 3
    mov dword ptr [r11+24], 5
    mov dword ptr [r11+28], 7
    mov r13, 14695981039346656037
    xor r14d, r14d
jk_loop:
    inc r14d
    cmp r14d, 16
    ja  jk_fvchk
    mov rax, 09E3779B97F4A7C15h
    imul rax, r14
    add rax, 1234h
    lea r11, jit_pbuf
    mov ecx, 400
jk_fill:
    mov rdx, 09E3779B97F4A7C15h
    add rax, rdx
    mov rdx, rax
    shr rdx, 30
    xor rdx, rax
    mov r8, 0BF58476D1CE4E5B9h
    imul rdx, r8
    mov r8, rdx
    shr r8, 27
    xor r8, rdx
    mov rdx, 094D049BB133111EBh
    imul r8, rdx
    mov rdx, r8
    shr rdx, 31
    xor rdx, r8
    mov qword ptr [r11], rdx
    add r11, 8
    dec ecx
    jnz jk_fill
    mov rcx, r12
    lea rdx, jit_pbuf
    lea r8, jit_cfg
    call jit_generate_program
    test eax, eax
    jz  jk_destroy
    mov rcx, r12
    call jit_get_codepos
    cmp eax, 448
    jbe jk_destroy
    cmp eax, 81664
    jae jk_destroy
    mov r15d, eax
    mov rcx, r12
    call jit_get_code
    add rax, 448
    mov r11, rax
    mov ecx, r15d
    sub ecx, 448
jk_fnv:
    movzx eax, byte ptr [r11]
    xor r13, rax
    mov rax, 1099511628211
    imul r13, rax
    inc r11
    dec ecx
    jnz jk_fnv
    mov ecx, r14d
    mov eax, 1
    shl eax, cl
    or  dword ptr [jk_flags], eax
    jmp jk_loop
jk_fvchk:
    mov rax, 0F25E8172A2BFCEE9h
    cmp r13, rax
    jne jk_destroy
    or  dword ptr [jk_flags], 20000h
jk_destroy:
    mov rcx, r12
    call jit_destroy
jk_chk:
    mov eax, dword ptr [jk_flags]
    lea r11, actual
    mov dword ptr [r11], eax
    lea r11, expect
    mov dword ptr [r11], 3FFFFh
    lea rcx, jk_name
    lea rdx, actual
    lea r8, expect
    mov r9, 4
    call check_match

    ; ---- vm flow: randomx_calculate_hash("abc"), zeroed dataset ----
    lea rcx, vmh_hex
    mov rdx, 64
    lea r8, expect
    call hex_decode
    mov dword ptr [vm_flags], 0
    mov rcx, 2181038016
    call mem_alloc
    test rax, rax
    jz  vmh_chk
    mov qword ptr [vmh_ds], rax
    mov qword ptr [vmh_dsq], rax
    mov dword ptr [vm_flags], 1
    mov ecx, 14
    xor edx, edx
    lea r8, vmh_dsq
    call randomx_create_vm
    test rax, rax
    jz  vmh_free
    mov qword ptr [vmh_vm], rax
    or  dword ptr [vm_flags], 2
    mov rcx, rax
    lea rdx, vmh_in
    mov r8d, 3
    lea r9, actual
    call randomx_calculate_hash
    xor ecx, ecx
vmh_cmp:
    lea r11, actual
    mov al, byte ptr [r11+rcx]
    lea r11, expect
    cmp al, byte ptr [r11+rcx]
    jne vmh_destroy
    inc ecx
    cmp ecx, 32
    jb  vmh_cmp
    or  dword ptr [vm_flags], 4
vmh_destroy:
    mov rcx, qword ptr [vmh_vm]
    call randomx_destroy_vm
vmh_free:
    mov rcx, qword ptr [vmh_ds]
    call mem_free
vmh_chk:
    lea r11, actual
    mov eax, dword ptr [vm_flags]
    mov dword ptr [r11], eax
    lea r11, expect
    mov dword ptr [r11], 7
    lea rcx, vmh_name
    lea rdx, actual
    lea r8, expect
    mov r9, 4
    call check_match

    ; ---- summary ----
    mov eax, dword ptr [tests_failed]
    lea rcx, hexbuf
    call fmt_u64
    lea r11, hexbuf
    mov byte ptr [r11+rax], 0
    lea rcx, hexbuf
    call print_cstr
    lea rcx, fail_cnt
    call print_line
    mov eax, dword ptr [tests_failed]
    add rsp, 48
    pop r14
    pop r13
    pop r12
    ret
run_self_tests ENDP

END
