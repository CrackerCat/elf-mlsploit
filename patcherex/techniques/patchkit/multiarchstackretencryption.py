import re
import logging
from patcherex.techniques.stackretencryption import *

l = logging.getLogger("patcherex.techniques.patchkit.MultiArchStackRetEncryption")

class MultiArchStackRetEncryption(StackRetEncryption):
    def __init__(self,binary_fname,backend,allow_reg_reuse=True):
        super(MultiArchStackRetEncryption, self).__init__(binary_fname, backend, allow_reg_reuse)

    def make_inline_encrypt(self, reg):
        inline_encrypt = self.patcher.arch.inline_encrypt(True)
        n_substitute = inline_encrypt.count("%s")
        return inline_encrypt % tuple([reg] * n_substitute)

    def function_to_patch_locations(self,ff):
        # TODO tail-call is handled lazily just by considering jumping out functions as not sane
        if cfg_utils.is_sane_function(ff) and cfg_utils.detect_syscall_wrapper(self.patcher,ff) == None \
                and not cfg_utils.is_floatingpoint_function(self.patcher,ff) and not ff.addr in self.safe_functions:
            # TODO: Filter out bad return sites using IDA
            # Currently, we filter out all functions that have multiple exits
            # We found bug that angr does not handle cxx_throw which is another exits
            if cfg_utils.is_longjmp(self.patcher,ff):
                self.found_longjmp = ff.addr
            elif cfg_utils.is_setjmp(self.patcher,ff):
                self.found_setjmp = ff.addr
            else:
                start = ff.startpoint
                ends = set()
                for ret_site in ff.ret_sites:
                    bb = self.patcher.project.factory.fresh_block(ret_site.addr, ret_site.size)
                    last_instruction = bb.capstone.insns[-1]
                    if not self.patcher.arch.is_ret(
                            "%s %s" % (last_instruction.mnemonic, last_instruction.op_str)):
                        msg = "bb at %s does not terminate with a ret in function %s"
                        l.debug(msg % (hex(int(bb.addr)),ff.name))
                        break
                    else:
                        ends.add(last_instruction.address)
                else:
                    if len(ends) == 0:
                        l.debug("cannot find any ret in function %s" %ff.name)
                    else:
                        return int(start.addr),map(int,ends) #avoid "long" problems

        l.debug("function %s has problems and cannot be patched" % ff.name)
        return None, None

    def get_instruction(self, e):
        # XXX: Is there a better way to get instruction?
        bb = self.patcher.cfg.get_any_node(e,anyaddr=True).block
        for insn in bb.capstone.insns:
            if insn.address == e:
                return insn
        raise ValueError("cannot find instruction at %x" % e)

    def get_common_patches(self):
        common_patches = []
        common_patches.append(AddRWDataPatch(self.patcher.project.arch.bytes,"rnd_xor_key"))
        common_patches.append(AddEntryPointPatch(self.patcher.arch.set_rnd_xor_key(),name="set_rnd_xor_key"))
        return common_patches

    def add_patch_at_bb(self, bb_addr, addr, is_tail=False):
        # TODO: Add inline patch for other architecture
        if is_tail:
            relavent_regs = ["ecx", "edx"]
        else:
            relavent_regs = ["eax", "ecx", "edx"]
        for r in relavent_regs:
            if self.is_reg_free(bb_addr, r, is_tail):
                inserted_code = self.make_inline_encrypt(r)
                if not is_tail:
                    # we add a nop so that indirectcfi will not see a pop at the beginning of a function
                    # this is a problem because indirectcfi does not like indirect calls to pop
                    inserted_code = "nop\n"+inserted_code
                return inserted_code
        self.need_safe_encrypt = True

        with self.patcher.arch.set_context(bb_addr):
            return self.patcher.arch.safe_inline_encrypt(not is_tail, self.get_instruction(addr))

    # TODO check if it is possible to do insane trick to always overwrite the same stuff and merge things
    def add_stackretencryption_to_function(self,start,ends):
        # in the grand-plan these patches have higher priority than, for instance, indirect jump ones
        # this only matters in case of conflicts
        l.debug("Trying adding stackretencryption to %08x %s"%(start,map(lambda x:hex(int(x)),ends)))
        headp = InsertCodePatch(start,self.add_patch_at_bb(start, start),name="stackretencryption_head_%d_%#x"%(self.npatch,start),priority=100)

        tailp = []
        for i,e in enumerate(ends):
            bb_addr = self.patcher.cfg.get_any_node(e,anyaddr=True).addr
            code = self.add_patch_at_bb(bb_addr, e, is_tail=True)
            tailp.append(InsertCodePatch(e,code,name="stackretencryption_tail_%d_%d_%#x"%(self.npatch,i,start),priority=100))

        for p in tailp:
            headp.dependencies.append(p)
            p.dependencies.append(headp)
        self.npatch += 1
        return [headp]+tailp

    def get_patches(self):
        common_patches = self.get_common_patches()

        # Disable safe_functions due to the bug in angr
        #self.safe_functions = self.get_safe_functions()
        self.safe_functions = set()

        cfg = self.patcher.cfg
        patches = []
        blacklisted_functions = self.find_savedretaccess_functions(cfg.functions)
        for k,ff in cfg.functions.iteritems():
            if ff.addr in blacklisted_functions:
                continue
            start,ends = self.function_to_patch_locations(ff)
            if start!=None and ends !=None:
                new_patches = self.add_stackretencryption_to_function(start,ends)
                l.info("added StackRetEncryption to function %s (%s -> %s)",ff.name,hex(start),map(hex,ends))
                patches += new_patches

        if self.need_safe_encrypt:
            # If two distinct functions for encrypting return addresses exist,
            # then add both two otherwise add only one
            safe_encrypt = self.patcher.arch.safe_encrypt()
            if isinstance(safe_encrypt, str):
                common_patches.append(AddCodePatch(safe_encrypt, name="safe_encrypt"))
            else:
                assert(isinstance(safe_encrypt, dict))
                for name, code in safe_encrypt.items():
                    common_patches.append(AddCodePatch(code, name=name))
        return common_patches + patches
