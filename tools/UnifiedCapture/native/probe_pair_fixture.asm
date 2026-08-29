option casemap:none

EXTERN RaiseFixtureSeh:PROC
EXTERN ExpectedReturn:QWORD

PUBLIC ProbeFaultMemory
PUBLIC ProbeFaultCall
PUBLIC ProbeEpilogue
PUBLIC ProbeEpilogueSite
PUBLIC ProbeLongEpilogue
PUBLIC ProbeLongEpilogueSite
PUBLIC ProbePopEpilogue
PUBLIC ProbePopEpilogueSite
PUBLIC ProbeRspTarget
PUBLIC ProbeRspCaller

.code

ProbeFaultMemory PROC
    mov rax, qword ptr [rcx]
    add rax, 1
    ret
ProbeFaultMemory ENDP

ProbeFaultCall PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    call RaiseFixtureSeh
    add rsp, 28h
    ret
ProbeFaultCall ENDP

ProbeEpilogue PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, rcx
ProbeEpilogueSite LABEL BYTE
    add rsp, 28h
    ret
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
ProbeEpilogue ENDP

; Exercises every instruction class present in the current game exit-window
; inventory: an optional NOP, stack restoration, nonvolatile POPs, and RET.
; This is intentionally longer than Gum's 5-byte near redirect so the report
; can state exactly how many source bytes the selected backend overwrote.
ProbeLongEpilogue PROC
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 198h
    mov rax, rcx
ProbeLongEpilogueSite LABEL BYTE
    nop
    add rsp, 198h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
ProbeLongEpilogue ENDP

; Places POP instructions inside the minimum near-redirect relocation span.
ProbePopEpilogue PROC
    push rbx
    push rsi
    push r14
    mov rax, rcx
ProbePopEpilogueSite LABEL BYTE
    pop r14
    pop rsi
    pop rbx
    ret
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
ProbePopEpilogue ENDP

ProbeRspTarget PROC
    mov rax, rcx
    nop
    nop
    nop
    nop
    nop
    ret
ProbeRspTarget ENDP

ProbeRspCaller PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    lea rax, RspAfterCall
    mov qword ptr [ExpectedReturn], rax
    call ProbeRspTarget
RspAfterCall:
    add rsp, 28h
    ret
ProbeRspCaller ENDP

END
