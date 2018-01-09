sub esp, 16

mov eax, 0
cpuid
mov [esp], ebx
mov [esp+4], edx
mov [esp+8], ecx
mov byte ptr [esp+12], 0

.readstr esp
