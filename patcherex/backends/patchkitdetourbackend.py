import copy
import os
import struct
import bisect
import logging
import tempfile
from collections import OrderedDict
from collections import defaultdict

import angr
import pwn
import patchkit.core

import patcherex
from patcherex import utils
from patcherex.patches import *
from patcherex.backends.patchkit.core.arch import arm

from ..backend import Backend
from .misc import ASM_ENTRY_POINT_PUSH_ENV, ASM_ENTRY_POINT_RESTORE_ENV
from .detourbackend import *

l = logging.getLogger("patcherex.backends.PatchkitDetourBackend")

class PatchkitDetourBackend(DetourBackend):
    def __init__(self, filename):
        # data_fallback== True: prevent using dump_segments
        super(PatchkitDetourBackend, self).__init__(filename, data_fallback=True, custom_base_addr=0)

        self.binary = patchkit.core.binary.Binary(filename, self)
        self.binary.verbose = True
        self.oep = self.binary.elf.entry

    @property
    def arch(self):
        return self.binary.arch

    def get_code_start(self):
        return self.binary.code.vaddr

    def get_current_code_position(self):
        return self.binary.next_alloc('code')

    def get_current_data_position(self):
        return self.binary.next_alloc('data')

    def dump_segments(self, tprint=False):
        # Never be used
        return

    def get_final_content(self):
        tmp = tempfile.NamedTemporaryFile(delete=False).name
        try:
            self.binary.save(tmp)
            return open(tmp, "rb").read()
        finally:
            os.remove(tmp)

    def resolve_name(self, code):
        import string

        # Allow partial substitution
        # from https://stackoverflow.com/questions/11283961/partial-string-formatting
        class FormatDict(dict):
            def __missing__(self, key):
                return "{" + key + "}"

        # Set ADDED_CODE_END before substitute names
        if 'ADDED_CODE_END' in self.name_map:
            del self.name_map['ADDED_CODE_END']
        self.name_map['ADDED_CODE_END'] = self.get_current_code_position()

        if self.name_map is not None:
            formatter = string.Formatter()
            mapping = FormatDict(**self.name_map)
            code = formatter.vformat(code, (), mapping)
        return code

    def get_oep(self):
        return self.oep

    def set_oep(self, new_oep):
        with self.binary.collect() as pt:
            pt.entry = new_oep

    def save_state(self,applied_patches):
        # Do we need to use deepcopy?
        self.saved_states[tuple(applied_patches)] = self.binary.get_state()

    def restore_state(self,applied_patches,removed_patches):
        # find longest sequence of patches for which we have a save state
        if len(removed_patches) > 0:
            cut = min([len(applied_patches)]+[applied_patches.index(p) for p in removed_patches if p in applied_patches])
            applied_patches = applied_patches[:cut]

        self.binary.set_state(self.saved_states[tuple(applied_patches)])
        #self.binary.elf.progs = self.saved_states[tuple(applied_patches)]
        #print "retrieving",applied_patches

        # cut dictionary to the current state
        todict = OrderedDict()
        for i,(k,v) in enumerate(self.saved_states.iteritems()):
            if i > self.saved_states.keys().index(tuple(applied_patches)):
                break
            todict[k]=v
        self.saved_states = todict

        return applied_patches

    def apply_patches(self, patches):
        self.remove_stackable_patches(patches)
        self.handle_add_label_patch(patches)
        self.check_relevant_patches(patches)

        # TODO: Support priority
        for patch in patches:            
            if isinstance(patch, RawMemPatch):
                with self.binary.collect() as pt:
                    pt.patch(patch.addr, raw=patch.data)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 1.1) AddRWDataPatch
        # 1.2) AddRWInitDataPatch
        rw_data_patches = [p for p in patches if isinstance(p,AddRWDataPatch) or isinstance(p, AddRWInitDataPatch)]

        for patch in rw_data_patches:
            addr = self.get_current_data_position()
            if isinstance(patch, AddRWDataPatch):
                data = "\x00" * patch.len
            else:
                assert(isinstance(patch, AddRWInitDataPatch))
                data = patch.data

            if patch.name is not None:
                self.name_map[patch.name] = addr
            with self.binary.collect() as pt:
                addr = pt.inject(raw=data, target='data')
            self.added_patches.append(patch)
            l.info("Added patch: " + str(patch))

        # 1.3) AddRODataPatch
        for patch in patches:
            addr = self.get_current_code_position()
            if isinstance(patch, AddRODataPatch):
                if patch.name is not None:
                    self.name_map[patch.name] = addr
                if self.arch.alignment:
                    # If it requires to be aligned (e.g.), make data aligned
                    if (len(patch.data) % self.arch.alignment) != 0:
                        patch.data += "\x00" * (self.arch.alignment + (len(patch.data) % self.arch.alignment))
                with self.binary.collect() as pt:
                    pt.inject(raw=patch.data, target='code')
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 2) AddCodePatch
        # resolving symbols
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                # TODO: Support C code injection
                assert(not patch.is_c)
                addr = self.get_current_code_position()
                if patch.name is not None:
                    self.name_map[patch.name] = addr
                with self.binary.collect() as pt:
                    pt.inject(asm=self.resolve_name(patch.asm_code))

        # 3) AddEntryPointPatch
        # basically like AddCodePatch but we detour by changing oep
        # and we jump at the end of all of them
        # resolving symbols
        if any([isinstance(p, AddEntryPointPatch) for p in patches]):
            # TODO: Support after_restore
            # TODO: Recover registers
            entrypoint_patches = [p for p in patches if isinstance(p,AddEntryPointPatch)]
            sorted_entrypoint_patches = sorted([p for p in entrypoint_patches if not p.after_restore], \
                key=lambda x:-1*x.priority)

            addr = self.get_current_code_position()

            # Do not use existing entry hook, but copy the code for name_map
            with self.binary.collect() as pt:
                asm = pt.arch.save_context
                for patch in sorted_entrypoint_patches:
                    self.added_patches.append(patch)
                    asm += self.resolve_name(patch.asm_code)
                    self.name_map[patch.name] = addr
                asm += pt.arch.restore_context
                asm += self.arch.switch_context(self.get_current_code_position(), pt.entry)

            with self.binary.collect(pt.entry) as pt:
                asm += self.arch.jmp(pt.entry)
                pt.entry = addr
                pt.inject(asm=asm)

        # 4) InlinePatch
        # we assume the patch never patches the added code
        for patch in patches:
            if isinstance(patch, InlinePatch):
                with self.binary.collect() as pt:
                    new_code = pt.arch.asm(patch.new_asm, patch.instruction_addr)
                    if patch.force_consistent_size:
                        assert len(new_code) == self.project.factory.block(patch.instruction_addr, num_inst=1).size
                    pt.patch(patch.instruction_addr, asm=self.resolve_name(patch.new_asm))
                    self.added_patches.append(patch)
                    l.info("Added patch: " + str(patch))

        # 5) InsertCodePatch
        # these patches specify an address in some basic block, In general we will move the basic block
        # and fix relative offsets
        # With this backend heer we can fail applying a patch, in case, resolve dependencies
        insert_code_patches = [p for p in patches if isinstance(p, InsertCodePatch)]
        insert_code_patches = sorted([p for p in insert_code_patches],key=lambda x:-1*x.priority)
        applied_patches = []
        while True:
            name_list = [str(p) if (p==None or p.name==None) else p.name for p in applied_patches]
            l.info("applied_patches is: |" + "-".join(name_list)+"|")
            assert all([a == b for a,b in zip(applied_patches,insert_code_patches)])
            for patch in insert_code_patches[len(applied_patches):]:
                    self.save_state(applied_patches)
                    try:                        
                        l.info("Trying to add patch: " + str(patch))                        
                        #new_code = self.insert_detour(patch, patch.force) 
                        new_code = self.insert_detour(patch, True) 

                        applied_patches.append(patch)
                        self.added_patches.append(patch)
                        l.info("Added patch: " + str(patch))
                    except (DetourException, MissingBlockException, DoubleDetourException) as e:
                        l.warning(e)
                        insert_code_patches, removed = self.handle_remove_patch(insert_code_patches,patch)
                        #print map(str,removed)
                        applied_patches = self.restore_state(applied_patches, removed)
                        l.warning("One patch failed, rolling back InsertCodePatch patches. Failed patch: "+str(patch))
                        break
                        # TODO: right now rollback goes back to 0 patches, we may want to go back less
                        # the solution is to save touched_bytes and ncontent indexed by applied patfch
                        # and go back to the biggest compatible list of patches
            else:
                break #at this point we applied everything in current insert_code_patches
                # TODO symbol name, for now no name_map for InsertCode patches

    def check_if_movable(self, thumb, instruction):
        # the idea here is an instruction is movable if and only if
        # it has the same string representation when moved at different offsets is "movable"

        #print "Patchkitbackend: check_if_movable"

        def bytes_to_comparable_str(arch, thumb, ibytes, offset):
            return " ".join(utils.instruction_to_str(arch.dis(ibytes, offset, thumb=thumb)[0]).split()[2:])

        # Check ip related instructions e.g. mov rbx, [rip + 0x100]
        if "[" + self.arch.ip  in instruction.op_str:
            return False
        
        instruction_bytes = str(instruction.bytes)
        pos1 = bytes_to_comparable_str(self.arch, thumb, instruction_bytes, 0x0)
        pos2 = bytes_to_comparable_str(self.arch, thumb, instruction_bytes, 0x07f00000)
        pos3 = bytes_to_comparable_str(self.arch, thumb, instruction_bytes, 0xfe000000)
        # print pos1, pos2, pos3
        if pos1 == pos2 and pos2 == pos3:
            return True
        else:
            return False

    def get_movable_instructions(self, block, force):
        # TODO there are two improvements here:
        # 1) being able to move the jmp and call at the end of a bb
        # 2) detect cases like call-pop and dependent instructions (which should not be moved)
        # get movable_instructions in the bb
        if force:
            # we do not check the instruction is movable or not
            return list(block.capstone.insns)

        movable_instructions = []
        capstone_block = block.capstone
        for insn in capstone_block.insns:
            if self.check_if_movable(capstone_block.thumb, insn):
                movable_instructions.append(insn)
            else:
                break

        return movable_instructions

    def find_detour_pos(self, block, detour_size, patch_addr, force):
        # iterates through the instructions to find where the detour can be stored
        movable_instructions = self.get_movable_instructions(block, force)
        detour_attempts = range(0, block.addr - patch_addr - 1, -1)

        movable_bb_start = movable_instructions[0].address
        movable_bb_size = self.project.factory.block(block.addr, num_inst=len(movable_instructions)).size
        l.debug("movable_bb_size: %d", movable_bb_size)
        l.debug("movable bb instructions:\n%s", "\n".join([utils.instruction_to_str(i) for i in movable_instructions]))
        l.debug("detour_size: %d", detour_size)

        # find a spot for the detour
        detour_pos = None
        for pos in detour_attempts:
            detour_start = patch_addr + pos
            detour_end = detour_start + detour_size - 1
            # Only allow the start of assembly since we might not have one-byte-nop
            if (detour_start >= movable_bb_start and detour_end < (movable_bb_start + movable_bb_size)
                and any([i.address == detour_start for i in movable_instructions])):
                detour_pos = detour_start
                break
        if detour_pos is None:
            raise DetourException("No space in bb", hex(block.addr), hex(block.size),
                                  hex(movable_bb_start), hex(movable_bb_size),
                                  hex(detour_size))
        else:
            l.debug("detour fits at %s", hex(detour_pos))

        return detour_pos

    def inject_moved_code(self, classified_instructions, patch_code, detour_pos, force):
        # create injected_code (pre, injected, culprit, post, jmp_back)
        with self.binary.collect(detour_pos) as pt:
            injected_code = ""
            injected_code += "\n".join([utils.capstone_to_gas(i)
                                        for i in classified_instructions
                                        if i.overwritten == 'pre']) + "\n"
            # injected_code = self.align_data(injected_code)
            injected_code += self.resolve_name(patch_code) + "\n"
            injected_code += "\n".join([utils.capstone_to_gas(i)
                                        for i in classified_instructions
                                        if i.overwritten == 'culprit']) + "\n"
            injected_code += "\n".join([utils.capstone_to_gas(i)
                                        for i in classified_instructions
                                        if i.overwritten == 'post']) + "\n"
            jmp_back_target = None
            for i in reversed(classified_instructions):  # jmp back to the one after the last byte of the last non-out
                if i.overwritten != "out":
                    jmp_back_target = i.address+len(str(i.bytes))
                    break
            assert jmp_back_target is not None
            pt.inject(asm=injected_code + self.arch.jmp(jmp_back_target))

    def insert_detour(self, patch, force):
        # TODO allow special case to patch syscall wrapper epilogue
        # (not that important since we do not want to patch epilogue in syscall wrapper)
        block_addr = self.get_block_containing_inst(patch.addr)
        block = self.project.factory.block(block_addr)

        l.info("inserting detour for patch: %s" % (map(hex, (block_addr, block.size, patch.addr))))

        jmp = self.arch.asm(asm=self.arch.jmp(self.get_current_code_position()), addr=patch.addr)
        detour_size = len(jmp)

        # get movable instructions
        movable_instructions = self.get_movable_instructions(block, force)
        if len(movable_instructions) == 0:
            raise DetourException("No movable instructions found", hex(block.addr), hex(block.size))

        # figure out where to insert the detour
        detour_pos = self.find_detour_pos(block, detour_size, patch.addr, force)

        # TODO: Optimize when we have one byte nop
        # classify overwritten instructions
        # We need to move all instruction before patch.addr
        detour_overwritten_bytes = range(detour_pos, max(detour_pos+detour_size, patch.addr))

        for i in movable_instructions:
            if len(set(detour_overwritten_bytes).intersection(set(range(i.address, i.address+len(i.bytes))))) > 0:
                if i.address < patch.addr:
                    i.overwritten = "pre"
                elif i.address == patch.addr:
                    i.overwritten = "culprit"
                else:
                    i.overwritten = "post"
            else:
                i.overwritten = "out"
        l.info("\n".join([utils.instruction_to_str(i) for i in movable_instructions]))
        assert any([i.overwritten != "out" for i in movable_instructions])

        # replace overwritten instructions with nops
        for i in movable_instructions:
            if i.overwritten != "out":
                for b in xrange(i.address, i.address+len(i.bytes)):
                    """
                    if b in self.touched_bytes:
                        raise DoubleDetourException("byte has been already touched: %08x" % b)
                    else:
                        self.touched_bytes.add(b)
                    """
                    self.touched_bytes.add(b)

        with self.binary.collect(detour_pos) as pt:
            detour_jmp_code = self.arch.asm(asm=self.arch.jmp(self.get_current_code_position()), addr=detour_pos)
            assert(len(detour_jmp_code) == detour_size)
            pt.patch(detour_pos, raw=detour_jmp_code)
        self.inject_moved_code(movable_instructions, patch.code, detour_pos, patch.force)
