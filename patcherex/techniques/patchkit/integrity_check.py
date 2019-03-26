import struct
import pwn

import patcherex
import angr
import re

import capstone
import logging
from patcherex.patches import *
from patcherex.backends.patchkitdetourbackend import PatchkitDetourBackend
from patcherex.backends.patchkit.core.util.elffile import DT
from patcherex.backends.patchkit.core.arch import x86, x86_64
from patcherex.backends.patchkit.core.util.rsa import rsa

l = logging.getLogger("patcherex.techniques.IntegrityCheck")

class IntegrityCheck(object):

    def __init__(self, binary_path, backend):
        self.binary_path = backend
        self.patcher = backend

        # TODO: Support for other backend
        assert(isinstance(backend, PatchkitDetourBackend))

    def find_init(self):
        # 4th argument of __libc_start_main is init
        bbl = self.patcher.project.factory.block(self.patcher.get_oep())
        node = self.patcher.cfg.get_any_node(bbl.addr)
        nlist = self.patcher.cfg.get_successors_and_jumpkind(node, excluding_fakeret=False)
        nlist = [n[0] for n in nlist if n[1] == 'Ijk_FakeRet']
        if nlist:
            bbl = nlist[0].block

        if isinstance(self.patcher.arch, x86_64):
            return self.find_init_x64(bbl)
        else:
            return self.find_init_i386(bbl)

    def _get_integrity_code(self, code_start, code_end, sumhash):
        if isinstance(self.patcher.arch, x86):
            with pwn.context.local(arch='i386'):
                return ("""
            push esi
            push edi
            push eax
            push ebx

            xor eax, eax
            call __get_my_ip_integrity_check
        __get_my_ip_integrity_check:
            pop esi
            sub esi, OFFSET __get_my_ip_integrity_check
            mov edi, esi
            add esi, {0}
            add edi, {1}

        __loop_integrity_check:
            movzx ebx, BYTE PTR [esi]
            add eax, ebx
            inc esi
            cmp esi, edi
            je __end_integrity_check
            jmp __loop_integrity_check

        __end_integrity_check:
            cmp eax, {2}
            je __exit_integrity_check
            """
            + pwn.shellcraft.exit(0) +
            """
        __exit_integrity_check:
            pop ebx
            pop eax
            pop edi
            pop esi
            """).format(code_start, code_end, sumhash)
        else:
            with pwn.context.local(arch='amd64'):
                return ("""
            push rsi
            push rdi
            push rax
            push rbx

            xor rax, rax
            call __get_my_ip_integrity_check
        __get_my_ip_integrity_check:
            pop rsi
            sub rsi, OFFSET __get_my_ip_integrity_check
            mov rdi, rsi
            add rsi, {0}
            add rdi, {1}

        __loop_integrity_check:
            movzx rbx, BYTE PTR [rsi]
            add rax, rbx
            inc rsi
            cmp rsi, rdi
            je __end_integrity_check
            jmp __loop_integrity_check

        __end_integrity_check:
            cmp rax, {2}
            je __exit_integrity_check
            """
            + pwn.shellcraft.exit(0) +
            """
        __exit_integrity_check:
            pop rbx
            pop rax
            pop rdi
            pop rsi
            """).format(code_start, code_end, sumhash)

    def find_init_i386(self, bbl):
        # TODO: Use DFG to get the value?
        vex = bbl.vex
        nstore = 0
        tmp = None
        hit_get = False
        offset = 0

        for s in reversed(bbl.vex.statements):
            if s.tag == 'Ist_Store':
                nstore += 1
                if nstore == 5: # 4th argument + call == 5
                    if s.expressions[1].tag == 'Iex_Const':
                        return int(str(s.expressions[1]), 16)
                    else:
                        tmp = s.expressions[1].tmp
            elif s.tag == 'Ist_WrTmp':
                if s.tmp == tmp:
                    if s.data.tag == 'Iex_Binop':
                        if s.data.op == 'Iop_Add32':
                            for arg in s.data.args:
                                if arg.tag == 'Iex_RdTmp':
                                    tmp = arg.tmp
                                elif arg.tag == 'Iex_Const':
                                    offset += int(str(arg), 16)
                                else:
                                    raise ValueError('No tag support for Iop_Add: %s' % arg.tag)
                        else:
                            raise ValueError('No support for Binop')
                    elif s.data.tag == 'Iex_Get':
                        # TODO: Need to confirm that this is really return address
                        hit_get = True
            elif s.tag == 'Ist_IMark' and hit_get:
                offset += s.addr
                return offset % (1<<32)
        raise ValueError('Cannot find init function')

    def find_init_x64(self, bbl):
        for i, insn in enumerate(bbl.capstone.insns):
            matches = re.findall(r"rcx, (0x[a-f0-9]+)", insn.op_str)
            if matches:
                return int(matches[0], 16)
            # PIE
            matches = re.findall(r"rcx, qword ptr \[rip \+ (0x[a-f0-9]+)\]", insn.op_str)
            if matches:
                next_insn = bbl.capstone.insns[i + 1]
                return int(matches[0], 16) + next_insn.address
        raise ValueError('Cannot find init function')

    def get_patches(self):
        # IntegrityCheck should be called after some patches are already applied
        assert(self.patcher.added_patches)
        patches = []
        init = self.find_init()
        l.info("Found init(): %x" % init)
        func = self.patcher.cfg.functions[init]
        max_block = max(func.blocks, key=lambda blk: blk.size)

        code_end = self.patcher.get_current_code_position()
        code_start = self.patcher.get_code_start()
        data = self.patcher.binary.elf.read(code_start, code_end - code_start)

        sumhash = 0
        for c in data:
            sumhash += c

        code = self._get_integrity_code(code_start, code_end, sumhash)
        patches.append(InsertCodePatch(max_block.addr,
            code=code, name="integrity_check") )

        return patches
