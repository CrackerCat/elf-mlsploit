import copy
import os
import sys
import struct
import bisect
import logging
import shutil
import tempfile
import mmap
from collections import OrderedDict
from collections import defaultdict

import pefile
import angr
import patchkit.core

from capstone import *
from keystone import *

import patcherex
from patcherex import utils
from patcherex.patches import *

from ..backend import Backend
from .misc import ASM_ENTRY_POINT_PUSH_ENV, ASM_ENTRY_POINT_RESTORE_ENV
from .detourbackend import *

l = logging.getLogger("patcherex.backends.PEDetourBackend")

section_R = 0x40000000
section_W = 0x80000000
section_X = 0x20000000
new_section_size = 0x1000


class PEDetourBackend(DetourBackend):
    def __init__(self, filename, patchpath):
        # data_fallback== True: prevent using dump_segments
        super(PEDetourBackend, self).__init__(filename, data_fallback=True)
        
        self.arch = None
        self.name = filename
        self.target_name = patchpath
        self.open(filename)        
        self.oep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.inst = {}
        self.executable_regions = {}
        self.code_patches = {}
        self.addcode_patches = []
        self.import_patches = {}
        self.name_map = {}
        self.disasm_code_section()

    def open(self, name):
        self.original_size = os.path.getsize(name)

        self.pe = pefile.PE(self.name)
        if self.pe.FILE_HEADER.Machine == 0x14c:
            self.arch = "x86"
        elif self.pe.FILE_HEADER.Machine == 0x200:
            self.arch = "ita"
        elif self.pe.FILE_HEADER.Machine == 0x8664:
            self.arch = "x64"
        return

    def addCodePatch(self, asm, name):
        addr = self.getLastAddress()
        code = self.assemble(asm, addr)
        self.addcode_patches.append([name, code])
        self.name_map[name] = addr

    def addSection(self, sectionName, data, chara):           
        number_of_section = self.pe.FILE_HEADER.NumberOfSections
        last_section = number_of_section - 1
        file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        new_section_offset = (self.pe.sections[number_of_section - 1].get_file_offset() + 40)

        # Look for valid values for the new section header
        raw_size = self.val_align(new_section_size, file_alignment)
        virtual_size = self.val_align(new_section_size, section_alignment)
        raw_offset = self.val_align((self.pe.sections[last_section].PointerToRawData +
                            self.pe.sections[last_section].SizeOfRawData),
                           file_alignment)

        virtual_offset = self.val_align((self.pe.sections[last_section].VirtualAddress +
                                self.pe.sections[last_section].Misc_VirtualSize),
                               section_alignment)
        
        characteristics = chara
        name = sectionName + ((8-len(sectionName)) * '\x00')

        # Create the section
        self.pe.set_bytes_at_offset(new_section_offset, name)
        self.pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
        self.pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
        self.pe.set_dword_at_offset(new_section_offset + 16, raw_size)
        self.pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
        self.pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
        self.pe.set_dword_at_offset(new_section_offset + 36, characteristics)

        # Edit the value in the File and Optional headers
        self.pe.FILE_HEADER.NumberOfSections += 1
        self.pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset

        # initialize with zeros(\x00) 
        self.pe.set_bytes_at_offset(raw_offset, "\x00"*new_section_size)
        # Write injected code to new section        
        self.pe.set_bytes_at_offset(raw_offset, data)

    #def apply_patches(self, name):
    def apply_patches(self):

        """
        for patch in patches:
            if isinstance(patch, RawMemPatch):
                self.patchkit.patch(patch.addr, raw=patch.data)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))
        """

        name = self.target_name
        shutil.copyfile(self.name, name)
        patch_codes = None

        # 1. resize file first                
        self.resize_file(filename=name, increasing_size=0x2000)
        self.original_size = os.path.getsize(name)
        
        # 2. generate patched code
        self.pe = pefile.PE(name)
        number_of_section = self.pe.FILE_HEADER.NumberOfSections
        last_section = number_of_section - 1
        raw_offset = self.pe.sections[last_section].PointerToRawData
        self.pe.OPTIONAL_HEADER.DllCharacteristics &= (0xFFFF ^ 0x40)

        patch_codes = ""
        patch_codes_size = 0
        code_start_addr = self.getLastAddress()
        target_addr = code_start_addr
        
        # 2. apply code patch (addcode)
        for inject_label, asm in self.addcode_patches:
            addr = self.name_map[inject_label]

            patch_codes += asm
            self.set_oep(addr)
            

        # 3. apply entrypoint patch
        for va, patch_code in self.code_patches:

            # TEST: temp
            pass
            section_offset = target_addr - self.align(va)

            # backup the original code (read 20 bytes and disasm)
            data = self.get_data_at_va(va, 20)
            codes, addr = self.disassemble(data, va=va)

            # return backup instructions (safely larger than 5 bytes)
            backup_code, ret_addr = self.get_backup_candidate(data, addr, 5)

            # replace original instructions with jmp
            jmp_code = self.assemble("jmp 0x%x" % target_addr, va)
            self.writeVA(va, jmp_code)

            # Resolve & insert phase
            asm = patch_code
            code = self.assemble(asm)
            patch_codes += code
            patch_codes += backup_code

            # jmp-back
            jmp_to_orig = self.assemble("jmp 0x%x" % (ret_addr), code_start_addr \
                + len(patch_codes))
            patch_codes += jmp_to_orig
            target_addr += len(code)

        self.getOffsetfromVA(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress + 
            self.pe.OPTIONAL_HEADER.ImageBase)
        
        patch_codes_size = len(patch_codes)
        print("Patch code size : ", patch_codes_size)

        # 3. add new section and dump patched code        
        #self.makeSection("morecode", patch_codes, section_R | section_X)
        self.addSection(".new", patch_codes, section_R | section_X)
        self.pe.write(filename=name)

        # 4 apply import table patch
        for prev_name, new_name in self.import_patches:
            self.patch_import_table(name, prev_name, new_name)
        
        return

    def _apply_patches(self, patches):
        self.remove_stackable_patches(patches)
        self.handle_add_label_patch(patches)
        self.check_relevant_patches(patches)

        # TODO: Support priority
        for patch in patches:
            if isinstance(patch, RawMemPatch):
                self.patchkit.patch(patch.addr, raw=patch.data)
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
                """
                with self.binary.collect() as pt:
                    pt.inject(asm=self.resolve_name(patch.asm_code))
                """

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
                pt.inject(asm=pt.arch.save_context)
                for patch in sorted_entrypoint_patches:
                    self.added_patches.append(patch)
                    pt.inject(asm=self.resolve_name(patch.asm_code), target='code')
                    self.name_map[patch.name] = addr
                pt.inject(asm=pt.arch.restore_context)
                pt.inject(asm=pt.arch.jmp(pt.entry))
                pt.entry = addr

        # 4) InlinePatch
        # we assume the patch never patches the added code
        for patch in patches:
            if isinstance(patch, InlinePatch):
                with self.binary.collect() as pt:
                    new_code = pt.arch.asm(patch.new_asm, patch.instruction_addr)
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
                        new_code = self.insert_detour(patch)
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


    def ret_import_tbl_addr(self):
        start_addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress + \
            self.pe.OPTIONAL_HEADER.ImageBase
        end_addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress + \
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].Size + \
            self.pe.OPTIONAL_HEADER.ImageBase
        
        out = {}
        out["start"] = start_addr
        out["end"] = end_addr
        return out

    def assemble(self, asm, org=0):
        if self.arch == "x86":
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
        else:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)

        code, count = ks.asm(asm, org)

        return "".join(map(lambda x: chr(x), code))

    def disassemble(self, opcodes, org=0, va=None):
        codes = []
        addr = []
        if self.arch == "x86":
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_64)

        for (address, size, mnemonic, op_str) in md.disasm_lite(opcodes, org):
            codes.append("%s %s" % (mnemonic, op_str))
            if va is not None:
                addr.append(va+address)            
        return codes, addr
    
    def getVAfromOffset(self, offset):
        for section in self.pe.sections:
            if(section.PointerToRawData <= offset and offset < section.PointerToRawData+section.SizeOfRawData):
                return self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + (offset - section.PointerToRawData)
        return 0
    
    def getOffsetfromVA(self, VA):
        RVA = VA - self.pe.OPTIONAL_HEADER.ImageBase
        for section in self.pe.sections:
            # print section
            if(section.VirtualAddress <= RVA and RVA < section.VirtualAddress+section.Misc_VirtualSize):
                # print section                
                return section.PointerToRawData + (RVA - section.VirtualAddress)
        return 0

    def get_data_at_va(self, va, size):
        RVA = va - self.pe.OPTIONAL_HEADER.ImageBase
        return self.pe.get_data(RVA)[:size]

    def get_import_func_addr(self, name):
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            #print entry.dll
            for imp in entry.imports:
                #print hex(imp.address), imp.name
                if imp.name == name:                    
                    return imp.address
        return None
    
    def writeVA(self, va, data):
        base = self.pe.OPTIONAL_HEADER.ImageBase
        self.pe.set_bytes_at_rva(va-base, data)
        return

    def val_align(self, val_to_align, alignment):
        return ((val_to_align + alignment - 1) / alignment) * alignment
    
    """
    @property
    def patchkit(self):
        with self.binary.collect() as pt:
            return pt
    """
    def retrieve_executable_regions(self):
        regions = self.cfg._executable_memory_regions()
        for region in regions:
            self.executable_regions[region[0]] = region[1] - region[0]

    def disasm_code_section(self): 
        self.retrieve_executable_regions() 
        for addr in self.executable_regions:#aw.executable_regions:
            size = self.executable_regions[addr]
            code = self.get_data_at_va(addr, size)
            
            instructions = self.decompile(code, addr)
            for inst in instructions:
                self.inst [format(int(inst.address),'X')] = [str(inst.mnemonic), str(inst.op_str)]
            #print self.inst

    def decompile(self, code, offset=0x0):
        if self.arch == "x86":
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_64)

        return list(md.disasm(code, offset))
    
    def get_code_start(self):  
        pass
        #return self.binary.code.vaddr

    def get_current_code_position(self):
        pass
        #return self.binary.next_alloc('code')

    def get_current_data_position(self):
        pass
        #return self.binary.next_alloc('data')

    def dump_segments(self, tprint=False):
        # Never be used
        return

    def get_oep(self):
        return self.oep

    def set_oep(self, new_oep):
        #with self.binary.collect() as pt:
        #    pt.entry = new_oep
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_oep        

    def align(self, sz):
        if (not sz % 0x1000):
            return sz
        else:
            return sz - sz%0x1000 + 0x1000

    def getLastAddress(self):
        section = self.pe.sections[-1]
        return self.pe.OPTIONAL_HEADER.ImageBase+section.VirtualAddress + \
            self.align(section.Misc_VirtualSize)
    
    def save(self, name):
        self.pe.OPTIONAL_HEADER.DllCharacteristics &= (0xFFFF ^ 0x40)
        self.pe.write(filename=name)
        return

    def get_backup_candidate(self, data, addr, size):
        init_addr = addr[0]
        for i in range(len(addr)):        
            inst_addr = addr[i] - init_addr
            if inst_addr >= size:                
                return data[:inst_addr], addr[i]
        return None, None

    def resize_file(self, filename, increasing_size=0x2000):
        # Resize the executable
        # Note: I added some more space to avoid error
        # TODO: check whether this is necessary or useless 
        fd = open(filename, 'a+b')
        map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
        map.resize(self.original_size + increasing_size)
        map.close()
        fd.close()

    """
    def get_final_content(self):
        tmp = tempfile.NamedTemporaryFile(delete=False).name
        try:
            self.binary.save(tmp)
            return open(tmp, "rb").read()
        finally:
            os.remove(tmp)
    """

    """
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
    """

    """
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
    """

    def check_if_movable(self, instruction):
        # the idea here is an instruction is movable if and only if
        # it has the same string representation when moved at different offsets is "movable"
        def bytes_to_comparable_str(ibytes, offset):
            return " ".join(utils.instruction_to_str(utils.decompile(ibytes, offset)[0]).split()[2:])

        # Check ip related instructions e.g. mov rbx, [rip + 0x100]
        if self.patchkit.arch.ip in instruction.op_str:
            return False

        instruction_bytes = str(instruction.bytes)
        pos1 = bytes_to_comparable_str(instruction_bytes, 0x0)
        pos2 = bytes_to_comparable_str(instruction_bytes, 0x07f00000)
        pos3 = bytes_to_comparable_str(instruction_bytes, 0xfe000000)
        # print pos1, pos2, pos3
        if pos1 == pos2 and pos2 == pos3:
            return True
        else:
            return False

    def get_movable_instructions(self, block):
        # TODO there are two improvements here:
        # 1) being able to move the jmp and call at the end of a bb
        # 2) detect cases like call-pop and dependent instructions (which should not be moved)
        # get movable_instructions in the bb
        original_bbcode = block.bytes
        with self.binary.collect() as pt:
            instructions = pt.arch.dis(original_bbcode, block.addr)

        movable_instructions = []
        for i in xrange(len(instructions)):
            if self.check_if_movable(instructions[i]):
                movable_instructions.append(instructions[i])
            else:
                break

        return movable_instructions

    def find_detour_pos(self, block, detour_size, patch_addr):
        # iterates through the instructions to find where the detour can be stored
        movable_instructions = self.get_movable_instructions(block)
        detour_attempts = range(0, block.addr - patch_addr - 1, -1)

        movable_bb_start = movable_instructions[0].address
        movable_bb_size = self.project.factory.block(block.addr, num_inst=len(movable_instructions)).size
        l.debug("movable_bb_size: %d", movable_bb_size)
        l.debug("movable bb instructions:\n%s", "\n".join([utils.instruction_to_str(i) for i in movable_instructions]))

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
                                  hex(movable_bb_start), hex(movable_bb_size))
        else:
            l.debug("detour fits at %s", hex(detour_pos))

        return detour_pos


    def inject_moved_code(self, classified_instructions, patch_code):
        # create injected_code (pre, injected, culprit, post, jmp_back)
        injected_code = ""
        injected_code += "".join([str(i.bytes)
                                    for i in classified_instructions
                                    if i.overwritten == 'pre'])

        injected_code += self.arch.asm(self.resolve_name(patch_code), self.get_current_code_position() + len(injected_code))
        injected_code += "".join([str(i.bytes)
                                    for i in classified_instructions
                                    if i.overwritten == 'culprit'])
        injected_code += "".join([str(i.bytes)
                                    for i in classified_instructions
                                    if i.overwritten == 'post'])
        jmp_back_target = None
        for i in reversed(classified_instructions):  # jmp back to the one after the last byte of the last non-out
            if i.overwritten != "out":
                jmp_back_target = i.address+len(str(i.bytes))
                break
        assert jmp_back_target is not None
        addr = self.patchkit.inject(raw=injected_code)
        self.patchkit.inject(asm=self.arch.jmp(jmp_back_target))

    def insert_detour(self, patch):
        # TODO allow special case to patch syscall wrapper epilogue
        # (not that important since we do not want to patch epilogue in syscall wrapper)
        block_addr = self.get_block_containing_inst(patch.addr)
        block = self.project.factory.block(block_addr)

        l.info("inserting detour for patch: %s" % (map(hex, (block_addr, block.size, patch.addr))))

        addr = self.get_current_code_position()
        detour_size = len(self.arch.asm(self.arch.jmp(self.get_current_code_position()), patch.addr))

        # get movable instructions
        movable_instructions = self.get_movable_instructions(block)
        if len(movable_instructions) == 0:
            raise DetourException("No movable instructions found")

        # figure out where to insert the detour
        detour_pos = self.find_detour_pos(block, detour_size, patch.addr)

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
                    if b in self.touched_bytes:
                        raise DoubleDetourException("byte has been already touched: %08x" % b)
                    else:
                        self.touched_bytes.add(b)
                #self.patch_bin(i.address, one_byte_nop*len(i.bytes))

        detour_jmp_code = self.arch.jmp(self.get_current_code_position())
        assert(len(self.arch.asm(detour_jmp_code, detour_pos)) == detour_size)
        self.patchkit.patch(detour_pos, asm=detour_jmp_code)
        self.inject_moved_code(movable_instructions, patch.code)
