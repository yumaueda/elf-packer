[BITS 64]

global loader_entry:function
global loader_size:data
global mprotect_offset:data
global unpack_offset:data

default rel

loader_size:     dq end - loader_entry
unpack_offset:   dq start_unpack - loader_entry

loader_entry:
    push rax
    push rcx
    push rdx
    push r12

start_unpack:
    mov rax, 0xAAAAAAAAAAAAAAAA
    mov rcx, 0xBBBBBBBBBBBBBBBB
    mov rdx, 0xCCCCCCCCCCCCCCCC
    sub r12, rax
    add rcx, r12

.loop_start xor byte [r12], dl
            ror rdx, 1
            inc r12
            cmp rcx, r12
            jnz .loop_start

    pop r12
    pop rdx
    pop rcx
    pop rax
    jmp 0xDDDDDDDD
end:
