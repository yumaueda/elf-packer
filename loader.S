[BITS 64]

global loader_entry:function
global loader_size:data
global mprotect_offset:data
global unpack_offset:data

default rel

section .text

loader_size:     dq end - loader_entry
mprotect_offset: dq mprotect - loader_entry
unpack_offset:   dq start_unpack - loader_entry

loader_entry:
    push rax
    push rcx
    push rdx

mprotect:
    mov rdi, 0xAAAAAAAAAAAAAAAA
    mov rsi, 0xBBBBBBBBBBBBBBBB
    mov rdx, 0x1 | 0x2 | 0x4    ; PROT_READ | PROT_WRITE | PROT
    mov rax, 0x10               ; mprotect
    syscall

    cmp rax, 0x0
    jz start_unpack

exit:
    mov rax, 0x60
    mov rdi, 0x1
    syscall

start_unpack:
    mov rax, 0xAAAAAAAAAAAAAAAA
    mov rcx, 0xBBBBBBBBBBBBBBBB
    mov rdx, 0xCCCCCCCCCCCCCCCC
    add rcx, rax

.loop_start xor byte [rax], dl
            ror rdx, 1
            inc rax
            cmp rcx, rax
            jnz .loop_start

   pop rdx
   pop rcx
   pop rax
   jmp 0xDDDDDDDD
end:
