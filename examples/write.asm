mov rax, 1
mov rdi, 1
.allocstr foo bar
mov rsi, $str0
mov rdx, 7
syscall
.show
