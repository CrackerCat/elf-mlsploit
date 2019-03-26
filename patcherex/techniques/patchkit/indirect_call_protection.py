import patcherex
import angr
from patcherex.patches import *
import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import re
import capstone
import logging
from collections import defaultdict
from ..indirectcfi import *

l = logging.getLogger("patcherex.techniques.patchkit.IndirectCallProtection")

class IndirectCallProtection(IndirectCFI):
    def __init__(self, binary_fname, backend):
        super(IndirectCallProtection, self).__init__(binary_fname, backend, True)

    def compile_mem_access(self, instruction):
        # I could use some compiler-like approach like the old cgrex, but I think it is overkill
        # instead, I just "copy" the code from capstone
        tstr = instruction.op_str.encode('ascii','ignore')
        instruction_str = instruction.mnemonic + " " + instruction.op_str
        # TODO if we move to keystone removing " ptr " may not be necessary
        # the problem here is that capstone writes prt and NASM does not like it
        rvalue = instruction.op_str.lower().encode("ascii")
        # this is a weird case it should never happen
        # if it happens it is better not to do anything since we change esp in our patch
        # TODO handle this better
        if self.patcher.arch.sp in rvalue:
            l.warning("found an indirect cj based on esp, it is better not to touch it")
            return None, None

        additional_patches = []
        match = re.match(r".*(0x[0-9a-fA-F]{7,8}).*",rvalue)
        if match != None:
            offset_str = match.group(1)
            label_patch_name = "indirectcfi_%#8X" % instruction.address
            offset_value = int(offset_str,16)
            rvalue = rvalue.replace(offset_str,"{"+label_patch_name+"}")
            additional_patches.append(AddLabelPatch(addr=offset_value,name=label_patch_name))

        l.info("Checking mem access of: %s --> %s" % (str(instruction), rvalue))
        return rvalue, additional_patches

    def get_safe_functions(self):
        return {}

    def get_common_patches(self):
        code = self.patcher.arch.indirect_call_protection()
        if isinstance(code, str):
            return [AddCodePatch(code, name='indirect_call_protection')]
        else:
            patches = []
            assert(isinstance(code, dict))
            for name, code in code.items():
                patches.append(AddCodePatch(code, name=name))
        return patches

    def handle_standard_cj(self,instruction,ff):
        rvalue, additional_patches = self.compile_mem_access(instruction)
        if rvalue == None:
            return []
        if self.patcher.arch.is_call(instruction):
            # Need to set_context to emit mode-dependent code
            with self.patcher.arch.set_context(instruction.address):
                new_code = self.patcher.arch.call_indirect_call_protection(rvalue)
        else:
            # TODO: Add protection for jmp *eax
            return []

        code_patch = InsertCodePatch(int(instruction.address),
                new_code,
                name = "indirect_cp_for_%08x" % instruction.address)
        return [code_patch] + additional_patches
