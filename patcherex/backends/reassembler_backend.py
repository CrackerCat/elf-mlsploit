
import logging
import os
import tempfile
import subprocess

l = logging.getLogger('patcherex.backends.reassembler_backend')

"""
try:
    import compilerex
except ImportError:
    l.warning('Cannot import compilerex. Reassembler backend will not be able to recompile assembly files.')
"""
import compilerex
import patcherex
import patchkit.core

from angr.analyses.reassembler import BinaryError
from patcherex import utils
from patcherex.patches import *

from ..patches import *
from ..backend import Backend
from ..errors import ReassemblerError, CompilationError, ReassemblerNotImplementedError
from .misc import ASM_ENTRY_POINT_PUSH_ENV, ASM_ENTRY_POINT_RESTORE_ENV

from patcherex.backends.patchkit.core.util import elffile

def stripping_format(s):
    return s.replace('{', '').replace('}', '')

class ReassemblerBackend(Backend):
    def __init__(self, filename, debugging=False, try_pdf_removal=True):

        super(ReassemblerBackend, self).__init__(filename, try_pdf_removal=try_pdf_removal)

        l.info("Reassembling %s...", os.path.basename(filename))
        filesize = os.stat(filename).st_size
        l.info('Original binary: %d bytes', filesize)

        self._debugging = debugging
        self._binary = None
        self.ncontent = self.ocontent

        self._compiler_stdout = None
        self._compiler_stderr = None

        self._raw_file_patches = [ ]
        self._add_segment_patches = [ ]

        self.executable_regions = {}  # key: start_addr, value: size of region
        self.inst = {}

        self.is_pie = self.check_pie(filename)
        if self.is_pie:
            l.info('PIE binary!')

        self._load()
        self.ret_executable_regions()
        self.get_instructions()
        
        # WEN: to co-operate with patchkit
        self.binary = patchkit.core.binary.Binary(filename, self)
        self.binary.verbose = True
        self.oep = self.binary.elf.entry

        self.name_map = dict()
        self._patches = dict()

    def append_patch(self, addr, asm):
        if addr in self._patches:
            self._patches[addr].append(asm)
        else:
            self._patches[addr] = [asm]

    def check_pie(self, filename):
        elfobj = open(filename, 'rb')
        elf = elffile.open(fileobj=elfobj)
        return elf.header.type == 3

    def ret_executable_regions(self):
        regions = self.cfg._executable_memory_regions()
        for region in regions:
            self.executable_regions[region[0]] = region[1] - region[0]

    def maddress_to_baddress(self, addr):
        """
        if addr >= self.max_convertible_address:
            msg = "%08x higher than max_convertible_address (%08x)" % (addr,self.max_convertible_address)
            raise InvalidVAddrException(msg)
        """
        baddr = self.project.loader.main_object.addr_to_offset(addr)
        if baddr is None:
            raise InvalidVAddrException(hex(addr))
        else:
            return baddr

    def get_memory_translation_list(self, address, size):
        # returns a list of address ranges that map to a given virtual address and size
        start = address
        end = address+size-1  # we will take the byte at end
        # print hex(start), hex(end)
        start_p = address & 0xfffffff000
        end_p = end & 0xfffffff000
        if start_p == end_p:
            return [(self.maddress_to_baddress(start), self.maddress_to_baddress(end)+1)]
        else:
            first_page_baddress = self.maddress_to_baddress(start)
            mlist = list()
            mlist.append((first_page_baddress, (first_page_baddress & 0xfffffff000)+0x1000))
            nstart = (start & 0xfffffff000) + 0x1000
            while nstart != end_p:
                mlist.append((self.maddress_to_baddress(nstart), self.maddress_to_baddress(nstart)+0x1000))
                nstart += 0x1000
            mlist.append((self.maddress_to_baddress(nstart), self.maddress_to_baddress(end)+1))
            return mlist

    def patch_bin(self, address, new_content):
        # since the content could theoretically be split into different segments we will handle it here
        ndata_pos = 0

        for start, end in self.get_memory_translation_list(address, len(new_content)):
            # print "-",hex(start),hex(end)
            ndata = new_content[ndata_pos:ndata_pos+(end-start)]
            self.ncontent = utils.str_overwrite(self.ncontent, ndata, start)
            ndata_pos += len(ndata)

    def read_mem_from_file(self, address, size):
        mem = ""
        for start, end in self.get_memory_translation_list(address, size):
            # print "-",hex(start),hex(end)
            mem += self.ncontent[start:end]
        return mem

    def get_instructions(self):
        for addr in self.executable_regions:
            code = self.read_mem_from_file(addr, self.executable_regions[addr])
            instructions = utils.decompile(code, addr)

            for inst in instructions:
                #print format(int(inst.address),'X'), inst.mnemonic, inst.op_str
                self.inst [format(int(inst.address),'X')] = "%s %s" % (str(inst.mnemonic), str(inst.op_str))

    #
    # Properties
    #
    @property
    def cfg(self):
        return self._binary.cfg

    @property
    def arch(self):
        return self.binary.arch

    #
    # Overriding public methods
    #

    def apply_patches(self, patches):

        entry_point_asm_before_restore = [ ]
        entry_point_asm_after_restore = [ ]

        for p in patches:
            if isinstance(p, InsertCodePatch):
                # self._binary.insert_asm(p.addr, p.att_asm())
                self.append_patch(p.addr, stripping_format(p.asm_code))
            elif isinstance(p, AddCodePatch):
                # self._binary.append_procedure(p.name, p.att_asm())
                asm = p.asm_code
                if p.name == 'safe_encrypt':
                    asm_lines = asm.split('\n')
                    add_line = asm_lines[7].replace('add', 'lea').replace('{rnd_xor_key}', '[rip + rnd_xor_key]')
                    asm = '\n'.join(asm_lines[:3] + [add_line] + asm_lines[8:])
                self._binary.append_procedure(p.name, stripping_format(asm))
            elif isinstance(p, AddRODataPatch):
                self._binary.append_data(p.name, p.data, len(p.data), readonly=True)
            elif isinstance(p, AddRWDataPatch):
                self._binary.append_data(p.name, None, p.len, readonly=False)

            elif isinstance(p, AddEntryPointPatch):
                if p.after_restore:
                    # entry_point_asm_after_restore.append(p.att_asm())
                    entry_point_asm_after_restore.append(p)
                else:
                    # entry_point_asm_before_restore.append(p.att_asm())
                    entry_point_asm_before_restore.append(p)

            elif isinstance(p, PointerArrayPatch):
                self._binary.append_data(p.name, p.data, len(p.data), readonly=False, sort='pointer-array')

            elif isinstance(p, RawFilePatch):
                self._raw_file_patches.append(p)

            elif isinstance(p, AddSegmentHeaderPatch):
                self._add_segment_patches.append(p)

            elif isinstance(p, AddLabelPatch):
                self._binary.add_label(p.name, p.addr)

            elif isinstance(p, RemoveInstructionPatch):
                self._binary.remove_instruction(p.ins_addr)

            else:
                raise ReassemblerNotImplementedError('ReassemblerBackend does not support patch %s. '
                                                     'Please bug Fish to implement it.' % type(p)
                                                     )

        entry_point_patches = entry_point_asm_before_restore + entry_point_asm_after_restore
        sorted_entry_point_patches = sorted([p for p in entry_point_patches if not p.after_restore], key=lambda x:-1*x.priority)

        for patch in sorted_entry_point_patches:
            asm = self.arch.save_context
            asm += stripping_format(patch.asm_code)
            asm += self.arch.restore_context
            self.append_patch(self.project.entry, stripping_format(asm))

        for addr in self._patches:
            self._binary.insert_asm(addr, '\n'.join(self._patches[addr]))

    def save(self, filename=None, assembly_path=None, assembly_only=False):

        # Get the assembly
        try:
            assembly = self._binary.assembly(comments=True, symbolized=True)
        except BinaryError as ex:
            raise ReassemblerError('Reassembler failed to reassemble the binary. Here is the exception we '
                                   'caught: %s' %
                                   str(ex)
                                   )

        # Save the assembly onto a temporary path
        if assembly_path is None:
            fd, tmp_file_path = tempfile.mkstemp(prefix=os.path.basename(self.project.filename), suffix=".s")
            os.write(fd, assembly)
            os.close(fd)
        else:
            tmp_file_path = assembly_path
            fd = open(tmp_file_path, 'wb')
            fd.write(assembly)
            fd.close()

        l.info("Generating assembly manifest at %s", tmp_file_path)

        if assembly_only:
            return

        dirpath = os.path.dirname(filename)
        try:
            os.makedirs(dirpath, 0755)
        except OSError:
            pass

        # compile it
        # res = compilerex.assemble([ tmp_file_path, '-mllvm', '--x86-asm-syntax=intel', '-o', filename ])
        retcode, res = compilerex.assemble([ tmp_file_path, '-o', filename ])

        self._compiler_stdout, self._compiler_stderr = res

        if retcode != 0:
            raise CompilationError("File: %s Error: %s" % (tmp_file_path,res))

        # Remove the temporary file
        if not self._debugging:
            os.remove(tmp_file_path)

        # strip the binary
        self._strip(filename)

        # apply raw file patches
        self._apply_raw_file_patches(filename)

        # add segments
        if self._add_segment_patches:
            self._add_segments(filename,self._add_segment_patches)

        return True

    def _add_segments(self, filename, patches):
        fp = open(filename)
        content = fp.read()
        fp.close()

        # dump the original segments
        old_segments = []
        header_size = 16 + 2*2 + 4*5 + 2*6
        buf = content[0:header_size]
        (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
            cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
            cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) = struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)
        phent_size = 8 * 4
        assert cgcef_phnum != 0
        assert cgcef_phentsize == phent_size
        pt_types = {0: "NULL", 1: "LOAD", 6: "PHDR", 0x60000000+0x474e551: "GNU_STACK", 0x6ccccccc: "CGCPOV2"}
        segments = []
        for i in xrange(0, cgcef_phnum):
            hdr = content[cgcef_phoff + phent_size * i:cgcef_phoff + phent_size * i + phent_size]
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align) = struct.unpack("<IIIIIIII", hdr)
            assert p_type in pt_types
            old_segments.append((p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align))

        # align size of the entire ELF
        content = utils.pad_str(content, 0x10)
        # change pointer to program headers to point at the end of the elf
        content = utils.str_overwrite(content, struct.pack("<I", len(content)), 0x1C)

        new_segments = [p.new_segment for p in patches]
        all_segments = old_segments + new_segments

        # add all segments at the end of the file
        for segment in all_segments:
            content = utils.str_overwrite(content, struct.pack("<IIIIIIII", *segment))

        # we overwrite the first original program header,
        # we do not need it anymore since we have moved original program headers at the bottom of the file
        content = utils.str_overwrite(content, "SHELLPHISH\x00", 0x34)

        # set the total number of segment headers
        content = utils.str_overwrite(content, struct.pack("<H", len(all_segments)), 0x2c)

        # update the file
        fp = open(filename,"wb")
        fp.write(content)
        fp.close()

    def _strip(self, path):
        """
        Strip the generated CGC binary.

        :param str path: Path to the CGC binary.
        :return: None
        """

        tmp_path = path + ".tmp"

        elf_header = "\177ELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"

        with open(path, "rb") as f:
            data = f.read()

        l.info("Before stripping: %d bytes", len(data))

        cgc_header = data[ : len(elf_header) ]

        data = elf_header + data[ len(elf_header) : ]

        with open(tmp_path, "wb") as f:
            f.write(data)

        r = subprocess.call(['strip', tmp_path])

        if r != 0:
            l.error("Stripping failed with exit code %d", r)
            return

        with open(tmp_path, "rb") as f1:
            with open(path, "wb") as f2:
                data = f1.read()

                l.info("After stripping: %d bytes", len(data))

                data = cgc_header + data[ len(cgc_header) : ]
                f2.write(data)

        os.remove(tmp_path)

    def _apply_raw_file_patches(self, filename):
        """
        Apply raw file patches on the patched binary.

        :param str filename: File path of the patched binary.
        :return: None
        """

        if not self._raw_file_patches:
            return

        with open(filename, "rb") as f:
            data = f.read()

        for p in self._raw_file_patches:  # type: RawFilePatch
            data = str_overwrite(data, p.data, p.file_addr)

        with open(filename, "wb") as f:
            f.write(data)

    def get_final_content(self):
        """
        Get the content of the patched binary.

        :return: Content of the patched binary.
        :rtype: str
        """

        # Save the binary at a temporary path
        fd, tmp_file_path = tempfile.mkstemp(prefix='reassembler_')
        os.close(fd)

        r = self.save(tmp_file_path)

        if not r:
            raise ReassemblerError('Reassembler fails. '
                                   'The compiler says: %s\n%s' % (self._compiler_stdout, self._compiler_stderr)
                                   )

        with open(tmp_file_path, "rb") as f:
            return f.read()


    #
    # Private methods
    #

    def _load(self):
        """
        Load and disassemble the binary.
        """

        try:
            self._binary = self.project.analyses.Reassembler(syntax='intel', is_pie=self.is_pie)
            self._binary.symbolize()
        except BinaryError as ex:
            raise ReassemblerError('Reassembler failed to load the binary. Here is the exception we caught: %s' % str(ex))
