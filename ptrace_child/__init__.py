from subprocess import Popen, PIPE
from pathlib import Path
import unicorn
from unicorn.x86_const import *

_dir = Path(__file__).parent.absolute()

class PtraceChild:
	# From /usr/include/sys/user.h
	USER_REGS = {
		'64': ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax', 'rip', 'cs', 'eflags', 'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs'],
		'32': ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'xds', 'xes', 'xfs', 'xgs', 'orig_eax', 'eip', 'xcs', 'eflags', 'esp', 'xss'],
	}

	def __init__(self, arch, mode):
		assert arch == 'X86'

		self.p = Popen([str(_dir / 'ptrace_child')], stdin=PIPE, stdout=PIPE)

		const = getattr(unicorn, '%s_const' % arch.lower())
		self.regd = {}
		for i, reg in enumerate(self.USER_REGS[mode]):
			uc_index = getattr(const, 'UC_%s_REG_%s' % (arch, reg.upper()), None)
			if uc_index != None:
				self.regd[uc_index] = i

	def _fix_arg(self, arg):
		if isinstance(arg, bytes):
			return arg

		return bytes(str(arg), 'ascii')

	def _write(self, *args):
		self.p.stdin.write(b' '.join(map(self._fix_arg, args)) + b'\n')
		self.p.stdin.flush()

	def _com(self, *args):
		self._write(*args)
		return self.p.stdout.readline()

	def mem_map(self, address, size):
		return int(self._com('mem_map', address, size), 0)

	def mem_read(self, address, size):
		self._write('mem_read', address, size)
		res = self.p.stdout.read(size)
		self.p.stdout.read(1)

		return res

	def mem_write(self, address, bs):
		self._com('mem_write', address, len(bs), bs)

	def reg_read(self, reg_index):
		return int(self._com('reg_read', self.regd[reg_index]), 0)

	def reg_write(self, reg_index, value):
		self._com('reg_write', self.regd[reg_index], value)

	def emu_start(self, start_address, stop_address):
		self._com('emu_start', start_address, stop_address)

	def mem_regions(self):
		# TODO?
		return []

if __name__ == '__main__':
	pc = PtraceChild('X86', '64')
	r = pc.mem_map(0, 0x1000)

	'''
		bs = b''
		i = 0
		while i < 20:
			pc.mem_write(r, bs)
			print(pc.mem_read(r, len(bs)))
			bs += bytes(chr(i), 'ascii')
			i += 1

		print()

		print(pc.reg_read(10))
		pc.reg_write(10, 1234)
		print(pc.reg_read(10))
	'''

	print('start_address:', r)

	from binascii import unhexlify
	code = unhexlify(b'48c7c0d2040000' + b'FFC0')
	print(code)
	pc.mem_write(r, code)
	print(pc.mem_read(r, 1))
	pc.emu_start(r, r + len(code))
	print('stop_address:', pc.reg_read(UC_X86_REG_RIP))
	print('RAX:', pc.reg_read(UC_X86_REG_RAX))

