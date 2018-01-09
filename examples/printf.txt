mov rbx, 0x0005d869
call rbx

and rsp, -16

.alloc 10
mov rax, 134217728

mov byte ptr [rax], '%'
mov byte ptr [rax+1], 'd'
mov byte ptr [rax+2], '\n'
mov byte ptr [rax+3], 0

mov rdi, rax
mov rsi, 434
mov rax, 0

mov rbx, 115360
mov rbx, 333838

.print rip
.readhex rbx 12

call rbx

.print rax
