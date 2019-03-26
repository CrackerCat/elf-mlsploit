import patcherex
import angr
import logging
import re
from collections import defaultdict

import pwn
import patcherex.cfg_utils as cfg_utils
from patcherex.patches import *
from patcherex.backends.patchkitdetourbackend import PatchkitDetourBackend
from patcherex.backends.patchkit.core.util.elffile import DT, ElfClass
from patcherex.backends.patchkit.core.arch import x86, x86_PIE, x86_64, x86_64_PIE

l = logging.getLogger("patcherex.techniques.patchkit.heapmanipulation")

class HeapManipulation(object):
    def __init__(self, filename, backend):
        self.filename = filename
        self.patcher = backend
        assert(isinstance(backend, PatchkitDetourBackend))

    def get_patches(self):
        patches = []
        elf = self.patcher.project.loader.main_object
        # patch for m(c)alloc
        # TODO : support x32 & x64 PIE InsertCodePatch()
        try:
            for symbol in ["malloc", "calloc"]:
                if symbol in elf.plt:
                    alloc = elf.plt[symbol]
                    alloc_got = elf.imports[symbol].rebased_addr
                    code_alloc = self.patcher.arch.randomize_malloc(alloc_got)
                    patches.append(InsertCodePatch(alloc, code_alloc, name="alloc randomization", force=True))
        except NotImplementedError:
            l.fatal("Cannot find allocation functions for %s" % self.patcher.arch)

        # patch for free
        if 'free' in elf.plt:
            free = elf.plt['free']
            code_free = self.patcher.arch.disable_free()
            patches.append(InlinePatch(free, code_free, force_consistent_size=False))
            #self.patcher.patchkit.patch(0x4004F0, asm=code_free)   # fastbin_dup_x64
            #self.patcher.patchkit.patch(0x6E0, asm=code_free)      # fastbin_dup_x64_pie
        return patches
