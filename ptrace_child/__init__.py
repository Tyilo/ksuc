from subprocess import Popen, PIPE
from pathlib import Path

_dir = Path(__file__).parent.absolute()

class PtraceChild:
	# From /usr/include/sys/user.h
	USER_REGS = {
		'64': ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax', 'rip', 'cs', 'eflags', 'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs'],
		'32': ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'xds', 'xes', 'xfs', 'xgs', 'orig_eax', 'eip', 'xcs', 'eflags', 'esp', 'xss'],
	}

	CODE_SIZE = 2**20

	def __init__(self, arch_info):
		arch = arch_info['arch']
		mode = arch_info['mode']
		assert arch == 'X86'
		assert mode in ['64', '32']

		self.p = Popen([str(_dir / ('ptrace_child%s' % mode))], stdin=PIPE, stdout=PIPE)
		self.regs = self.USER_REGS[mode]

		address = self.alloc(self.CODE_SIZE)
		self.reg_write(arch_info['instruction_pointer'], address)

	def stop(self):
		self.p.kill()
		self.p.wait()

		self.p.stdin.close()
		self.p.stdout.close()

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

	def _reg_index(self, reg):
		return self.regs.index(reg.lower())

	def reg_read(self, reg):
		return int(self._com('reg_read', self._reg_index(reg)), 0)

	def reg_write(self, reg, value):
		self._com('reg_write', self._reg_index(reg), value)

	def mem_read(self, address, size):
		self._write('mem_read', address, size)
		res = self.p.stdout.read(size)
		self.p.stdout.read(1)

		return res

	def mem_write(self, address, bs):
		self._com('mem_write', address, len(bs), bs)

	def alloc(self, size):
		return int(self._com('alloc', size), 0)

	def start(self, start_address, stop_address):
		self._com('start', start_address, stop_address)


import unittest

class TestX86_64(unittest.TestCase):
	def setUp(self):
		arch_info = {
			'arch': 'X86',
			'mode': '64',
			'instruction_pointer': 'RIP',
		}
		self.emu = PtraceChild(arch_info)
		self.mem = self.emu.alloc(0x1000)

	def tearDown(self):
		self.emu.stop()

	def test_mem(self):
		bs = b''
		i = 0
		while i < 20:
			self.emu.mem_write(self.mem, bs)
			self.assertEqual(bs, self.emu.mem_read(self.mem, len(bs)))

			bs += bytes(chr(i), 'ascii')
			i += 1

	def	test_reg(self):
		self.emu.reg_write('rbx', 1234)
		self.assertEqual(self.emu.reg_read('rbx'), 1234)

	def test_code(self):
		from binascii import unhexlify
		# mov rax, 5678; inc eax
		code = unhexlify(b'48c7c02e160000' + b'ffc0')
		self.emu.mem_write(self.mem, code)

		end = self.mem + len(code)
		self.emu.start(self.mem, end)

		self.assertEqual(self.emu.reg_read('rip'), end)
		self.assertEqual(self.emu.reg_read('rax'), 5679)


class TestX86_32(unittest.TestCase):
	def setUp(self):
		arch_info = {
			'arch': 'X86',
			'mode': '32',
			'instruction_pointer': 'EIP',
		}
		self.emu = PtraceChild(arch_info)
		self.mem = self.emu.alloc(0x1000)
		print(self.mem)

	def tearDown(self):
		self.emu.stop()

	def test_mem(self):
		bs = b''
		i = 0
		while i < 20:
			self.emu.mem_write(self.mem, bs)
			self.assertEqual(bs, self.emu.mem_read(self.mem, len(bs)))

			bs += bytes(chr(i), 'ascii')
			i += 1

	def	test_reg(self):
		self.emu.reg_write('ebx', 1234)
		self.assertEqual(self.emu.reg_read('ebx'), 1234)

	def test_code(self):
		from binascii import unhexlify
		# mov eax, 5678; inc eax
		code = unhexlify(b'b82e160000' + b'40')
		self.emu.mem_write(self.mem, code)

		end = self.mem + len(code)
		self.emu.start(self.mem, end)

		#self.assertEqual(self.emu.reg_read('eip'), end)
		self.assertEqual(self.emu.reg_read('eax'), 5679)

if __name__ == '__main__':
	unittest.main()
