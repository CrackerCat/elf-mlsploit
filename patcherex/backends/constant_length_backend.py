import logging
import os

import pwn
from patcherex.patches import *
from ..backend import Backend

l = logging.getLogger('patcherex.backends.ConstantLengthBackend')

class ConstantLengthBackend(Backend):
    """
    Backend that does not change size of backend.
    This is the most reliable backend that we designed.
    It only supports RawMemPatch and InlinePatch.
    """

    def __init__(self, filename, try_pdf_removal=True):
        super(ConstantLengthBackend, self).__init__(filename, try_pdf_removal)
        self._filename = filename
        self._binary = pwn.elf.ELF(filename)

    def apply_patches(self, patches):
        for patch in patches:
            if isinstance(patch, RawMemPatch):
                self._binary.write(patch.addr, patch.data)
            if isinstance(patch, InlinePatch):
                self._binary.asm(patch.instruction_addr, patch.new_asm)

    def save(self, filename=None):
        if filename is None:
            filename = self._filename
        self._binary.save(filename)
        os.chmod(filename, 0774)
