.code
EXTERN PairRuntimeBlockBody:PROC

PUBLIC PairRuntimeTarget
PairRuntimeTarget PROC
    mov rax, qword ptr [rcx]
    add rax, rdx
    mov qword ptr [rcx], rax
    db 16 dup (090h)
PairRuntimeTargetExit::
    db 15 dup (090h)
    ret
PairRuntimeTarget ENDP

PUBLIC PairRuntimeRecursive
PairRuntimeRecursive PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    test edx, edx
    jz PairRuntimeRecursiveBase
    dec edx
    call PairRuntimeRecursive
    inc rax
    jmp PairRuntimeRecursiveDone
PairRuntimeRecursiveBase:
    mov rax, qword ptr [rcx]
PairRuntimeRecursiveDone:
    add rsp, 28h
PairRuntimeRecursiveExit::
    db 15 dup (090h)
    ret
PairRuntimeRecursive ENDP

PUBLIC PairRuntimeBlock
PairRuntimeBlock PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    call PairRuntimeBlockBody
    add rsp, 28h
    db 16 dup (090h)
PairRuntimeBlockExit::
    db 15 dup (090h)
    ret
PairRuntimeBlock ENDP

END
