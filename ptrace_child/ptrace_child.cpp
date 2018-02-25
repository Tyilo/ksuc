#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sched.h>

#include <string>
#include <iostream>
#include <fstream>
#include <vector>

#ifdef __x86_64__
typedef uint64_t regval_t;
#define IP rip
#else
typedef uint32_t regval_t;
#define IP eip
#endif

#define REG_INDEX(reg) (offsetof(struct user_regs_struct, reg) / sizeof(regval_t))

std::ofstream log;

long _ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data, const char * request_name) {
	errno = 0;
	long r = ptrace(request, pid, addr, data);
	if (errno != 0) {
		log << request_name << ": " << strerror(errno) << std::endl;
	}
	return r;
}

#define PTRACE(request, pid, addr, data) _ptrace(request, pid, (void *)(addr), (void *)(data), #request)

pid_t child_pid;
volatile void * newest_allocation;

uint8_t test[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};

void child_allocate(size_t length) {
	newest_allocation = mmap(NULL, length, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);

	__asm__("int3");
}

std::vector<char> read_bytes(size_t address, size_t size) {
	std::vector<char> buffer(size);
	char * bytes = buffer.data();
	size_t num_words = size / sizeof(long);
	size_t extra_bytes = size % sizeof(long);

	for (int i = 0; i < num_words; i++) {
		long value = PTRACE(PTRACE_PEEKDATA, child_pid, address + i * sizeof(long), 0);
		memcpy(bytes + i * sizeof(long), &value, sizeof(long));
	}

	if (extra_bytes) {
		size_t offset = num_words * sizeof(long);
		long value = PTRACE(PTRACE_PEEKDATA, child_pid, address + offset, 0);
		memcpy(bytes + offset, &value, extra_bytes);
	}

	return buffer;
}

char read_byte(size_t address) { return read_bytes(address, 1)[0]; }

void write_bytes(size_t address, const std::vector<char> & buffer) {
	size_t size = buffer.size();
	const char * bytes = buffer.data();
	const long * words = reinterpret_cast<const long *>(bytes);
	size_t num_words = size / sizeof(long);
	size_t extra_bytes = size % sizeof(long);

	for (int i = 0; i < num_words; i++) {
		PTRACE(PTRACE_POKEDATA, child_pid, address + i * sizeof(long), words[i]);
	}

	if (extra_bytes) {
		size_t offset = num_words * sizeof(long);
		long value = PTRACE(PTRACE_PEEKDATA, child_pid, address + offset, 0);
		memcpy(&value, bytes + offset, extra_bytes);
		PTRACE(PTRACE_POKEDATA, child_pid, address + offset, value);
	}
}

void write_value(size_t address, regval_t value) {
	char * bytes = reinterpret_cast<char *>(&value);
	write_bytes(address, {bytes, bytes + sizeof(regval_t)});
}

regval_t get_reg(size_t reg_index) {
	struct user_regs_struct regs;
	struct iovec iov = {&regs, sizeof(regs)};
	PTRACE(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov);

	return reinterpret_cast<regval_t *>(&regs)[reg_index];
}

void write_reg(size_t reg_index, regval_t value) {
	struct user_regs_struct regs;
	struct iovec iov = {&regs, sizeof(regs)};
	PTRACE(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov);

	reinterpret_cast<regval_t *>(&regs)[reg_index] = value;

	PTRACE(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov);
}

void * allocate(size_t length) {
	struct user_regs_struct gregs;
	struct iovec iov = {&gregs, sizeof(gregs)};
	PTRACE(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov);

	struct user_regs_struct new_regs = gregs;
#ifdef __x86_64__
	new_regs.rip = (regval_t)&child_allocate;
	new_regs.rdi = length;
#else
	new_regs.eip = (regval_t)&child_allocate;
	new_regs.esp -= 4;
	write_value(new_regs.esp, length);
#endif
	iov.iov_base = &new_regs;
	PTRACE(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov);

	PTRACE(PTRACE_CONT, child_pid, 0, 0);
	wait(NULL);

	void * res = (void *)PTRACE(PTRACE_PEEKDATA, child_pid, &newest_allocation, 0);

	iov.iov_base = &gregs;
	PTRACE(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov);

	return res;
}

int child_main(void *) {
	PTRACE(PTRACE_TRACEME, 0, 0, 0);
	raise(SIGSTOP);
	return 0;
}

int main() {
	std::vector<char> child_stack(1000);
	child_pid = clone(child_main, child_stack.data() + 1000, 0, NULL);

	log.open("/tmp/ptrace_child.log");

	log << "test: " << &test << std::endl;

	PTRACE(PTRACE_SEIZE, child_pid, 0, 0);
	wait(NULL);

	std::string cmd;
	while (std::cin >> cmd) {
		if (cmd == "alloc") {
			log << "mem_map" << std::endl;
			size_t size;
			std::cin >> size;
			std::cout << allocate(size) << std::endl;
		} else if (cmd == "mem_write") {
			log << "mem_write" << std::endl;
			size_t address, size;
			std::cin >> address >> size;

			char c;
			std::cin.read(&c, 1);
			std::vector<char> buffer(size);
			std::cin.read(buffer.data(), size);

			write_bytes(address, buffer);

			log << "mem_write done" << std::endl;
			std::cout << std::endl;
		} else if (cmd == "mem_read") {
			log << "mem_read" << std::endl;
			size_t address, size;
			std::cin >> address >> size;

			//address = (regval_t)&test;

			std::vector<char> buffer = read_bytes(address, size);
			std::cout.write(buffer.data(), buffer.size());

			log << "mem_read done" << std::endl;

			std::cout << std::endl;
		} else if (cmd == "reg_write") {
			log << "reg_write" << std::endl;
			size_t index, value;
			std::cin >> index >> value;

			write_reg(index, value);

			std::cout << std::endl;
		} else if (cmd == "reg_read") {
			log << "reg_read" << std::endl;
			size_t index;
			std::cin >> index;

			regval_t value = get_reg(index);
			std::cout << value << std::endl;

			log << value << std::endl;
		} else if (cmd == "start") {
			log << "start" << std::endl;
			size_t start_address, stop_address;
			std::cin >> start_address >> stop_address;

			{
				char bbb = read_byte(start_address);
				log << "first: " << (int)bbb << std::endl;
			}

			char replaced_byte = read_byte(stop_address);
			write_bytes(stop_address, {'\xcc'});

			write_reg(REG_INDEX(IP), start_address);

			PTRACE(PTRACE_CONT, child_pid, 0, 0);
			wait(NULL);

			write_bytes(stop_address, {replaced_byte});
			write_reg(REG_INDEX(IP), stop_address);

			std::cout << std::endl;
		} else {
			log << "unknown: " << cmd << std::endl;
			std::cerr << "Unknown command: " << cmd << std::endl;
			return 1;
		}
	}

	log << "dead" << std::endl;
}
