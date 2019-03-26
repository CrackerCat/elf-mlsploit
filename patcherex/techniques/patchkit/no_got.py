import struct
import pwn

import patcherex
import angr

import capstone
import logging
from patcherex.patches import *
from patcherex.backends.patchkitdetourbackend import PatchkitDetourBackend
from patcherex.backends.patchkit.core.util.elffile import DT, ElfClass
from patcherex.backends.patchkit.core.arch import x86, x86_PIE, x86_64, x86_64_PIE
from patcherex.backends.patchkit.core.util.rsa import rsa

l = logging.getLogger("patcherex.techniques.patchkit.NoGot")

class NoGot(object):
    def __init__(self, binary_path, backend):
        self.binary_path = binary_path
        self.patcher = backend
        # TODO: Support for other backend
        assert(isinstance(backend, PatchkitDetourBackend))

    def get_patches(self):
        patches = []
        main_obj = self.patcher.project.loader.main_object
        # Since elffile.py does not parse plt entries,
        # we use pwntools to find plt entries
        for name, addr in main_obj.plt.iteritems():
            # jmp 0x6
            plt_start_addr = main_obj.sections_map['.plt'].vaddr
            raw = self.patcher.arch.asm(asm=self.patcher.arch.jump_over_got(addr, plt_start_addr), addr=addr)
            patches.append(RawMemPatch(addr, raw))
        return patches
