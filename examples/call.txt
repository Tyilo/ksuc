jmp body; f: imul rax, 2; ret; body: mov rax, 27; call f
.print rax
