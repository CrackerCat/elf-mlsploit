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

SECTIONS_TO_PATCH = ['.rodata', '.bss', '.data']

class RemoveShFlags(object):

    def __init__(self, binary_path, backend):
        self.binary_path = backend
        self.patcher = backend
        # TODO: Support for other backend
        assert(isinstance(backend, PatchkitDetourBackend))

    def post_process(self):
        elf = self.patcher.binary.elf
        for section_name in SECTIONS_TO_PATCH:
            section = elf.section_by_name(section_name)
            section.flags = 0

