sub rsp, 16

mov rax, 0
cpuid
mov [rsp], ebx
mov [rsp+4], edx
mov [rsp+8], ecx
mov byte ptr [rsp+12], 0

.readstr rsp
