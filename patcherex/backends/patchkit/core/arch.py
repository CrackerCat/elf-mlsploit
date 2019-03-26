import logging
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager

import pwn
import compiler
from util.elffile import EM
from capstone import *
from keystone import *

l = logging.getLogger('patcherex.backends.patchkit.core.arch')

# Used for making variable in pwntools
RSA_DIR = os.path.join(os.path.dirname(__file__), "util/rsa")
RSA_C_PATH = os.path.join(RSA_DIR, "rsa.c")

def create_arch(binary, backend):
    machine = EM[binary.elf.header.machine]
    assert(binary.elf.header.type in [2, 3])
    pie = binary.elf.header.type == 3

    if machine == EM['EM_386']:
        if pie:
            return x86_PIE(binary, backend)
        else:
            return x86(binary, backend)
    elif machine == EM['EM_X86_64']:
        if pie:
            return x86_64_PIE(binary, backend)
        else:
            return x86_64(binary, backend)
    elif machine == EM['EM_ARM']:
        if pie:
            return arm_PIE(binary, backend)
        else:
            return arm(binary, backend)
    elif machine == EM['EM_AARCH64']:
        if pie:
            return aarch64_PIE(binary, backend)
        else:
            return aarch64(binary, backend)
    else:
        raise NotImplementedError("Unknown machine: %s" % machine)

class Arch(object):
    _llc_opts = None

    def __init__(self, binary, backend):
        self.binary = binary
        self.cs = Cs(*self._cs)
        self.cs.detail = True
        self.ks = Ks(*self._ks)
        self.backend = backend

        self.is_att = False

    @property
    def ip(self):
        raise NotImplementedError

    @property
    def sp(self):
        raise NotImplementedError

    @property
    def cc(self):
        raise NotImplementedError

    @property
    def objcopy(self):
        raise NotImplementedError

    @property
    def cflags(self):
        raise NotImplementedError

    @property
    def word_size(self):
        """
        Machine word size
        """
        raise NotImplementedError

    def asm(self, asm, addr, additional=""):
        # TODO: Use pwntools' asm function
        # TODO: Find out where this log level is set
        logging.getLogger('pwnlib.asm').setLevel('INFO')
        if not asm:
            return ''

        with pwn.context.local(arch=self._pwntools_arch, log_level='error'):
            return pwn.asm(additional + asm, vma=addr)

    def dis(self, raw, addr=0, thumb=True):
        return list(self.cs.disasm(str(raw), addr))

    def compile(self, c_code):
        if self._llc_opts is None:
            raise NotImplementedError

        with tempfile.NamedTemporaryFile(suffix='.c') as c_src_f:
            with tempfile.NamedTemporaryFile(suffix='.ll') as ll_src_f:
                with tempfile.NamedTemporaryFile(suffix='.s') as dest_f:
                    c_src_f.write(c_code)
                    c_src_f.flush()
                    subprocess.call('clang-6.0 -Os -S -emit-llvm %s -o %s' % (
                        c_src_f.name,
                        ll_src_f.name
                    ), shell=True)

                    subprocess.call('llc-6.0 -O3 %s %s -o %s' % (
                        ll_src_f.name,
                        self._llc_opts,
                        dest_f.name
                    ), shell=True)
                    assembly_output = file(dest_f.name, 'r').read()
                    assembly_output_clean = ''
                    label_prefix = '_LBB_' + os.urandom(8).encode('hex')
                    for line in assembly_output.split('.cfi_startproc')[1].split('.Lfunc_end0')[0].split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#') and not line.startswith('.cfi_'):
                            line = line.replace('.LBB', label_prefix)
                            assembly_output_clean += line + '\n'
                    return assembly_output_clean

    def use_att(self):
        self.is_att = True

    def jmp(self, dst, src=None):
        # Code for jmp
        raise NotImplementedError

    def call(self, dst):
        raise NotImplementedError

    def bzero(self, dst, size):
        raise NotImplementedError

    def ret(self):
        raise NotImplementedError

    def nop(self):
        raise NotImplementedError

    @property
    def save_context(self):
        raise NotImplementedError

    @property
    def restore_context(self):
        raise NotImplementedError

    """
    Code for StackRetEncryption
    """
    def inline_encrypt(self, enter):
        """
        Inline code for encrypt a return address
        """
        raise NotImplementedError

    def safe_inline_encrypt(self, enter, instr):
        """
        Inline code for calling 'safe_encrypt'
        """
        raise NotImplementedError

    def safe_encrypt(self):
        """
        A function that encrypt a return address
        This function can return code
        or a dictionary that contains name and code
        """
        raise NotImplementedError

    def set_rnd_xor_key(self):
        # Should return a function that sets {rnd_xor_key}
        raise NotImplementedError

    def call_backdoor(self, flag_path, pub_key):
        raise NotImplementedError

    @property
    def alignment(self):
        return 0

    def is_ret(self, instruction_str):
        """
        Determine whether the instruction is return or not
        """
        raise NotImplementedError

    def is_call(self, instruction):
        """
        Determine whether the instruction is call or not
        """
        raise NotImplementedError

    def switch_context(self, src, dst):
        """
        Code for changing context bewteen src & dst
        This is used only for change mode (Thumb & ARM) in ARM
        """
        return ''

    @contextmanager
    def set_context(self, src):
        """
        Set context according to 'src' address
        This is used to generate 'src' related code
        e.g., if src is thumb mode, generate thumb mode code
        """
        yield

    def normalize_addr(self, addr):
        """
        Normalize address according to architecture
        e.g., ARM requires to drop last bit since it represents only mode
        """
        return addr

    def jump_over_got(self, plt_start_addr, addr):
        """
        Jump over GOT to prevent GOT overwriting
        """
        raise NotImplementedError

    # Heap function protection
    def disable_free(self):
        """
        Code to disable free()
        """
        raise NotImplementedError

    def randomize_malloc(self, got):
        """
        Code to randomize malloc()
        """
        raise NotImplementedError

    # Indirect call protection
    def indirect_call_protection(self):
        """
        Function that checks indirect call target
        """
        raise NotImplementedError

    def call_indirect_call_protection(self, target):
        """
        Call 'indirect_call_protection' to check the target
        """
        raise NotImplementedError

    def pushstr_xor(self, string, append_null=True):
        """
        push string using XOR encryption
        """
        if append_null:
            string += "\x00"
        word_size = self.word_size
        while len(string) % word_size != 0:
            string += "A"

        word_size = self.word_size
        asm = "// push %s\n" % repr(string)
        with pwn.context.local(randomize=True):
            avoid = string + '\x00' + '\n'
            for i in xrange(len(string), 0, -word_size):
                word = string[i-word_size:i]
                a, b = pwn.util.fiddling.xor_pair(word, avoid)
                a, b = map(self.unpack_word, [a, b])
                asm += self._pushword_xor(a, b)
        return asm + "\n"


class x86_common(Arch):
    _llc_opts = '-march=x86 --x86-asm-syntax=intel'

    @property
    def cc(self):
        return 'gcc'

    @property
    def objcopy(self):
        return 'objcopy'

    def call(self, dst):
        return 'call %s;' % dst

    def jmp(self, dst, src=None):
        return 'jmp %s;' % dst

    def ret(self): return 'ret;'
    def nop(self): return 'nop;'

    def inline_encrypt(self, enter):
        return '''
            pop %s;
            xor %s, [{rnd_xor_key}];
            push %s;
        '''

    def safe_inline_encrypt(self, enter, instr):
        return '''
            call {safe_encrypt}
        '''

    def is_ret(self, instruction_str):
        # Accept both ret and retn
        return instruction_str.startswith("ret")

    def is_call(self, instruction):
        return instruction.mnemonic == "call"

    def jump_over_got(self, plt_start_addr, addr):
        return "jmp $+6"

    def disable_free(self):
        return "ret"

class x86(x86_common):
    _cs = CS_ARCH_X86, CS_MODE_32
    _ks = KS_ARCH_X86, KS_MODE_32
    _pwntools_arch = 'i386'

    @property
    def cflags(self):
        return ["-m32", '-mno-sse', '-masm=intel']

    @property
    def ip(self):
        return "eip"

    @property
    def sp(self):
        return "esp"

    @property
    def word_size(self):
        return 4

    def pack_word(self, i):
        return pwn.p32(i)

    def unpack_word(self, s):
        return pwn.u32(s)

    def _pushword_xor(self, a, b):
        return (
            "push {a}\n"
            "xor dword ptr [{sp}], {b}\n"
        ).format(a=a, b=b, sp=self.sp)

    # memcpy should be pc-relative
    # dst and src are offsets from the _PKST_ label
    def memcpy(self, dst, src, size):
        return '''
        push edi
        push esi
        push ecx

        call ref
        ref: pop edi
        sub edi, ref - _start
        mov esi, edi

        add edi, %d
        add esi, %d
        mov ecx, %d

        rep movsb

        pop ecx
        pop esi
        pop edi
        ''' % (dst, src, size)

    def bzero(self, dst, size):
        return '''
        push esi
        push edi
        mov edi, {0}
        mov esi, {1}
_bzero_start:
        cmp esi, 0
        je _bzero_end
        mov BYTE PTR [edi], 0
        inc edi
        dec esi
        jmp _bzero_start
_bzero_end:
        pop edi
        pop esi
        '''.format(dst, size)

    @property
    def save_context(self):
        # Assume that edi is not used...
        return """
        pusha
        """

    @property
    def restore_context(self):
        return """
        popa
        """

    def safe_encrypt(self):
        return '''
            push ecx
            push edx
            call 1f
        1:
            pop edx
            sub edx, OFFSET 1b
            add edx, {rnd_xor_key}
            mov ecx, [esp+12]
            xor ecx, [edx]
            mov [esp+12], ecx
            pop edx
            pop ecx
            ret
        '''

    def set_rnd_xor_key(self):
        asm = "pusha\n"
        asm += """
        mov edi, esp /* edi will not be used */
        call 1f
    1:
        pop esi
        sub esi, OFFSET 1b
        add esi, {rnd_xor_key}
        """
        asm += self.pushstr_xor('/dev/urandom')
        asm += pwn.shellcraft.i386.open("esp", 0)
        asm += pwn.shellcraft.i386.read('eax', 'esi', 4)
        asm += pwn.shellcraft.i386.close('ebx')
        asm += "mov esp, edi\n"
        asm += "popa\n"
        return asm

    def call_backdoor(self, flag_path, pub_key):
        # TODO: Refactor with x86 code
        asm = ""
        asm += self.bzero("esp", 132) # Cleanup buffer for safety
        asm += self.pushstr_xor(flag_path)
        asm += pwn.shellcraft.i386.open('esp', 0)
        asm += pwn.shellcraft.i386.read('eax', 'esp', 127)
        asm += """
            mov edi, esp
            call 1f
    1:
            pop esi
            sub esi, OFFSET 1b
            add esi, {%s}
            push esi
            push edi
            lea esi, [esp-0x400]
            push esi
            call rsaenc     /* _rsaenc(res, data, n) */
            lea esi, [esp-0x400 + 4]
        """ % pub_key
        asm += pwn.shellcraft.i386.write(1, 'esi', 132)
        asm += pwn.shellcraft.i386.exit(0)

        asm += open(os.path.join(RSA_DIR, "rsa_x86.s")).read()
        return asm

    def none_alphanumeric_backdoor(self, flag_path, pub_key="rsa_n"):
        cnv2noneAN_code = """
        int cnv2noneAN(char *str, int str_len)
        {
            char tmp[] = "\x00\x01\x02\x03\x04\x05\x06\x08\x0E";
            char result[8*128] = {0,};
            int total_len = 0;
            for(int i = 0; i < str_len; i++)
            {
                int shift_num = 1;
                for (int j = 0; j < 8; ++j)
                {
                    if(*str & shift_num)
                    {
                        result[total_len] = tmp[j];
                        total_len++;
                    }
                    shift_num <<= 1;
                }
                result[total_len] = tmp[8];
                total_len++;
                str++;
            }
            *(char **)str = result;
            return total_len;
        }
        """

        asm = """
            cmp_eq:
                sub esp, 0x200
                mov [ebp-0x8],ecx
            """
        asm += self.bzero("esp", 0x190)  # Cleanup buffer for safety
        asm += self.pushstr_xor(flag_path)
        asm += pwn.shellcraft.i386.open('esp', 0)
        asm += pwn.shellcraft.i386.read('eax', 'esp', 127)
        asm += """
                mov edi, esp
                call 1f
        1:
                pop esi
                sub esi, OFFSET 1b
                add esi, {%s}
                push esi
                push edi
                lea esi, [esp+0x90]
                push esi
                call rsaenc     /* _rsaenc(res, data, n) */
                lea esi, [esp+0x90 + 4]
                push 132
                push esi
                call _cnv2noneAN
                mov esi, [esp + 0x90 + 12 + 132]
            """ % pub_key
        asm += pwn.shellcraft.i386.write(1, 'esi', 'eax')
        asm += pwn.shellcraft.i386.exit(0)

        asm += open(os.path.join(RSA_DIR, "rsa_x86.s")).read()
        asm += compiler.compile(
            cnv2noneAN_code,
            self.binary.linker,
            arch=self)
        return asm

    def checksum_asm(self):
        elf = pwn.ELF(self.binary.path)
        get_base = """
        call ref
        ref: pop eax
        sub eax, OFFSET ref
        mov [ebp-0x4], eax
        """

        get_read_base_end="""
        xor ecx,ecx
        mov eax, [ebp-0x4]
        mov ebx, [eax + %d] # stdin addr
        reparse:
        mov edi, [ebx+4*7] # IO_read_base
        mov esi, [ebx+4*8] # IO_read_end

        test edi,edi
        jz stdin_ptr
        test esi,esi
        jz stdin_ptr
        jmp stdin_ok

        stdin_ptr:
            test ecx,ecx
            jnz exit
            add ecx, 1
            mov ebx, [ebx]
            jmp reparse
        """%elf.symbols['stdin']
        # TODO: Support other trigger method

        checksum="""
        stdin_ok:
        xor eax, eax
        loop_checksum:
            mov edx, [edi]
            add eax, edx
            add edi, 4
            cmp esi, edi
            jne loop_checksum
        push eax
        """

        write_checksum = pwn.shellcraft.i386.write(0, 'esp', 4)

        pexit = """
        exit:
        xor ebx,ebx
        push 1
        pop eax
        int 0x80
        """

        added_code = get_base + get_read_base_end + checksum + write_checksum + pexit
        return added_code

    def backdoor_asm(self, csum_addr, flag_path, rsa_enable=True, pub_key="rsa_n"):
        #open read time (nanosleep or alarm)
        elf = pwn.ELF(self.binary.path)

        get_base = """
        call ref
        ref: pop eax
        sub eax, OFFSET ref
        mov [ebp-0x4], eax
        """

        get_read_base_end="""
        xor ecx,ecx
        mov eax, [ebp-0x4]
        mov ebx, [eax + %d] # stdin addr
        reparse:
        mov edi, [ebx+4*7] # IO_read_base
        mov esi, [ebx+4*8] # IO_read_end

        test edi,edi
        jz stdin_ptr
        test esi,esi
        jz stdin_ptr
        jmp stdin_ok

        stdin_ptr:
            test ecx,ecx
            jnz exit
            add ecx, 1
            mov ebx, [ebx]
            jmp reparse
        """%elf.symbols['stdin']
        # TODO: Support other trigger method

        checksum="""
        stdin_ok:
        xor eax, eax
        loop_checksum:
            mov edx, [edi]
            add eax, edx
            add edi, 4
            cmp esi, edi
            jne loop_checksum
        """

        cmp_checksum="""
        mov ebx, [ebp - 0x4]
        add ebx, %d #checksum base addr
        mov esi, [ebx] #total checksum num
        xor ecx, ecx
        add ebx, 4
        loop_cmp_checksum:
            mov edx, [ebx+ecx*4]
            cmp eax, edx
            je cmp_eq
            add ecx, 1
            cmp ecx, esi
            jne loop_cmp_checksum

        exit:
            xor ebx,ebx
            push 1
            pop eax
            int 0x80
        """% csum_addr

        read_flag = """
                    cmp_eq:
                        sub esp, 0x200
                        mov [ebp-0x8],ecx
                    """
        if rsa_enable:
            read_flag += self.bzero("esp", 0x190)  # Cleanup buffer for safety
            read_flag += self.pushstr_xor(flag_path)
            read_flag += pwn.shellcraft.i386.open('esp', 0)
            read_flag += pwn.shellcraft.i386.read('eax', 'esp', 127)
            read_flag += """
                        mov edi, esp
                        call 1f
                1:
                        pop esi
                        sub esi, OFFSET 1b
                        add esi, {%s}
                        push esi
                        push edi
                        lea esi, [esp+0x90]
                        push esi
                        call rsaenc     /* _rsaenc(res, data, n) */
                        lea esi, [esp+0x90 + 4]
                        mov esp, esi
                    """ % pub_key

        else:
            read_flag += self.pushstr_xor(flag_path)
            read_flag += pwn.shellcraft.i386.open('esp', 0)
            read_flag += pwn.shellcraft.i386.read('eax', 'esp', 0x7F)


        post_sleep = pwn.shellcraft.i386.time(0)
        post_sleep += """
        and eax, 7
        mov ecx, [ebp-0x8]
        movzx ebx, byte ptr[esp+ecx]
        mov ecx, eax
        mov edx, 0x80
        shr edx, cl
        and ebx, edx
        test ebx, ebx
        jz exit
        """
        sleep_exit = """
        push 0
        push 1
        mov eax, 162 #nanosleep
        mov ebx, esp
        mov ecx, 0
        int 0x80

        jmp exit
        """

        rsa_asm = open(os.path.join(RSA_DIR, "rsa_x86.s")).read()

        added_code = get_base + get_read_base_end + checksum + cmp_checksum + read_flag + post_sleep + sleep_exit +rsa_asm
        return added_code

    def call_indirect_call_protection(self, target):
        return '''
        push edx
        mov edx, %s
        call {indirect_call_protection}
        pop edx
        ''' % target

    def indirect_call_protection(self):
        if not hasattr(self, 'indirect_call_protection_counter'):
            setattr(self, 'indirect_call_protection_counter', 0)
        self.indirect_call_protection_counter += 1

        indirect_call_protection_func = self.compile("""
        #include <stdint.h>

        #define memcmp __builtin_memcmp
        #define FIND_ELF_HEADER(x) {while (*(uint32_t *)x != 0x464c457f) x -= 0x1000;}
        #define GADGET_PROTECTION 1
        #define TARGET_ELF_CHECK 2
        #define TARGET_REGION_CHECK 4
        #define TARGET_ALIGNMENT_CHECK 8
        #define PLT_CALL_BLOCK 16

        uint64_t indirect_call_protection(unsigned char *addr, unsigned char *pc, int prot) {
            unsigned char *search;

            // gadget protection
            if (prot & GADGET_PROTECTION) {
                unsigned char *addr_bak = addr;

                // skip nop
                if (*addr == 0x90) {
                    addr++;
                }

                // follow short jump or cond jump
                if (*addr == 0xeb || (*addr >= 0x70 && *addr <= 0x7f)) {
                    addr = (addr + 2) + *((uint8_t *)(addr + 1));
                }

                // skip nop
                if (*addr == 0x90) {
                    addr++;
                }

                // pop reg
                if (*addr >= 0x58 && *addr <= 0x5f)
                    return GADGET_PROTECTION;

                // add esp
                if (!memcmp(addr, "\\x83\\xc4", 2))
                    return GADGET_PROTECTION;

                // leave
                if (*addr == 0xc9)
                    return GADGET_PROTECTION;

                addr = addr_bak;
            }

            if (prot & PLT_CALL_BLOCK) {
                // plt
                if (
                    !memcmp(addr, "\\xff\\x25", 2) &&
                    *(addr + 6) == 0x68 &&
                    *(addr + 11) == 0xe9
                    )
                    return PLT_CALL_BLOCK;

                // plt + 6
                if (
                    !memcmp(addr - 6, "\\xff\\x25", 2) &&
                    *(addr - 6 + 6) == 0x68 &&
                    *(addr - 6 + 11) == 0xe9
                    )
                    return PLT_CALL_BLOCK;
            }

            // target elf check
            search = (unsigned char *)((uint64_t)addr & (~0xfff));
            if (prot & TARGET_ELF_CHECK) {
                // no ELF header -> crash
                FIND_ELF_HEADER(search);
            }

            // target region check
            unsigned char *lower_bound = pc - 0x1000000;
            unsigned char *upper_bound = (unsigned char *)((uint64_t)pc & (~0xfff));
            if (prot & TARGET_REGION_CHECK) {
                if ((int64_t)addr < (int64_t)lower_bound || addr > upper_bound)
                    return TARGET_REGION_CHECK;
            }

            // target alignment check
            if (prot & TARGET_ALIGNMENT_CHECK) {
                int alignment_ok = 0;

                // good
                if (((uint64_t)addr & 0xf) == 0)
                    alignment_ok = 1;

                // nop
                if (*(addr - 1) == 0x90)
                    alignment_ok = 1;

                // ret
                if (*(addr - 1) == 0xc3)
                    alignment_ok = 1;

                // jmp / call
                if (*(addr - 5) == 0xe9 || *(addr - 5) == 0xe8) {
                    // check destination
                    unsigned char *dest = (addr + 5) + *((uint32_t *)(addr - 4));

                    if ((int64_t)dest > (int64_t)lower_bound && dest < upper_bound)
                        alignment_ok = 1;
                }

                // jmp short
                if (*(addr - 2) == 0xeb)
                    alignment_ok = 1;

                // xchg    ax, ax
                if (!memcmp(addr - 2, "\\x66\\x90", 2))
                    alignment_ok = 1;

                // lea esi, [esi]
                if (!memcmp(addr - 3, "\\x8d\\x76\\x00", 3))
                    alignment_ok = 1;

                // lea esi, [esi]
                if (!memcmp(addr - 4, "\\x8d\\x74\\x26\\x00", 4))
                    alignment_ok = 1;

                // lea edi, [edi]
                if (!memcmp(addr - 7, "\\x8d\\xbc\\x27", 3) && !memcmp(addr - 7 + 3, "\\x00\\x00\\x00\\x00", 4))
                    alignment_ok = 1;

                if (!alignment_ok)
                    return TARGET_ALIGNMENT_CHECK;
            }

            return 0;
        }
        """)

        return '''
        push eax
        push ecx
        push edx

        push {protection_level}
        call _indirect_call_protection_get_pc_{nonce}
        _indirect_call_protection_get_pc_{nonce}:
        push edx
        call _indirect_call_protection_func_{nonce}
        add esp, 12
        test eax, eax
        jz _indirect_call_protection_pass_{nonce}
        hlt
        _indirect_call_protection_pass_{nonce}:

        pop edx
        pop ecx
        pop eax
        ret

        _indirect_call_protection_func_{nonce}:
        {func}
        '''.format(
            func=indirect_call_protection_func,
            nonce=str(self.indirect_call_protection_counter) + '_' + os.urandom(4).encode('hex'),
            protection_level=(1|2|4|8|16),
        )

    def randomize_malloc(self, got):
        asm = ""
        with pwn.context.local(arch=self._pwntools_arch):
            asm += """
                push ebx
                push ecx
                push edx
                push esi
                mov esi, esp
            """

            asm += self.pushstr_xor('/dev/urandom')
            asm += pwn.shellcraft.i386.open("esp", 0)          # SYS_open(5)
            asm += pwn.shellcraft.read('eax', 'esp', 4)        # SYS_read(3)
            asm += pwn.shellcraft.close('ebx')                 # SYS_close(6)

            # malloc(size + rand(0x10))
            asm += """
                pop eax
                /* and eax, 0xF masking */
                and eax, 0xFF /* rand(0x100) */

                mov esp, esi
                pop esi
                pop edx
                pop ecx
                pop ebx

                add [esp+8], eax
                call 1f
            1:
                pop eax
                sub eax, OFFSET 1b
                add eax, %s
                jmp [eax]
            """ % got

        return asm

class x86_PIE(x86):
    def inline_encrypt(self, enter):
        # TODO: Find a way to encode return address only using one register
        return '''
        call 1f
    1:
        pop %s
        sub %s, OFFSET 1b
        add %s, {rnd_xor_key}
        mov %s, [%s]
        xor [esp], %s
        '''


class x86_64(x86_common):
    _cs = CS_ARCH_X86, CS_MODE_64
    _ks = KS_ARCH_X86, KS_MODE_64
    _pwntools_arch = 'amd64'

    _llc_opts = '-march=x86-64 --x86-asm-syntax=intel'

    @property
    def cflags(self):
        return ['-mno-sse', '-masm=intel']

    @property
    def ip(self):
        return "rip"

    @property
    def sp(self):
        return "rsp"

    @property
    def word_size(self):
        return 8

    def pack_word(self, i):
        return pwn.p64(i)

    def unpack_word(self, s):
        return pwn.u64(s)

    def _pushword_xor(self, a, b):
        return (
            "mov rax, {a}\n"
            "push rax\n"
            "mov rax, {b}\n"
            "xor qword ptr [{sp}], rax\n"
        ).format(a=a, b=b, sp=self.sp)

    def memcpy(self, dst, src, size):
        return '''
        push rdi
        push rsi
        push rcx

        lea rdi, [rip - _start + %d]
        lea rsi, [rip - _start + %d]
        mov rcx, %d

        rep movsb

        pop rcx
        pop rsi
        pop rdi
        ''' % (dst, src, size)

    @property
    def save_context(self):
        # TODO: Optimize this...
        if not self.is_att:
            return """
            push rax
            push rdi
            push rsi
            push rdx
            push rcx
            push r8
            push r9
            push r10
            mov r10, rsp
            """
        else:
            return """
            pushq %rax
            pushq %rdi
            pushq %rsi
            pushq %rdx
            pushq %rcx
            pushq %r8
            pushq %r9
            pushq %r10
            movq %rsp, %r10
            """

    @property
    def restore_context(self):
        if not self.is_att:
            return """
            mov rsp, r10
            pop r10
            pop r9
            pop r8
            pop rcx
            pop rdx
            pop rsi
            pop rdi
            pop rax
            """
        else:
            return """
            mov %r10, %rsp
            pop %r10
            pop %r9
            pop %r8
            pop %rcx
            pop %rdx
            pop %rsi
            pop %rdi
            pop %rax
            """

    def bzero(self, dst, size):
        return '''
        push rsi
        push rdi
        mov rdi, {0}
        mov rsi, {1}
_bzero_start:
        cmp rsi, 0
        je _bzero_end
        mov BYTE PTR [rdi], 0
        inc rdi
        dec rsi
        jmp _bzero_start
_bzero_end:
        pop rdi
        pop rsi
        '''.format(dst, size)

    def call_backdoor(self, flag_path, pub_key):
        with pwn.context.local(arch='amd64'):
            # TODO: Use type variable for pwntools
            asm = "mov r9, rsp\n"
            asm += self.bzero("r9", 132) # Cleanup buffer for safety
            asm += self.pushstr_xor(flag_path)
            asm += pwn.shellcraft.open('rsp', 0)
            asm += pwn.shellcraft.read('rax', 'r9', 127)
            asm += """
            call 1f
        1:
            pop rdx
            sub rdx, OFFSET 1b
            add rdx, {%s}
            mov rsi, r9
            lea rdi, [rsp+0x400]
            call _rsaenc     /* _rsaenc(res, data, n) */
            lea rsi, [rsp+0x400]
            """ % pub_key
            asm += pwn.shellcraft.write(1, 'rsi', 132)
            asm += pwn.shellcraft.exit(0)

            rsa_c_code = open(RSA_C_PATH).read()
            asm += compiler.compile(
                    rsa_c_code,
                    self.binary.linker,
                    arch=self)
            return asm

    def none_alphanumeric_backdoor(self, flag_path, pub_key="rsa_n"):
        with pwn.context.local(arch='amd64'):
            cnv2noneAN_code = """
            int cnv2noneAN(char *str, int str_len)
            {
                char tmp[] = "\x00\x01\x02\x03\x04\x05\x06\x08\x0E";
                char result[8*128] = {0,};
                int total_len = 0;
                for(int i = 0; i < str_len; i++)
                {
                    int shift_num = 1;
                    for (int j = 0; j < 8; ++j)
                    {
                        if(*str & shift_num)
                        {
                            result[total_len] = tmp[j];
                            total_len++;
                        }
                        shift_num <<= 1;
                    }
                    result[total_len] = tmp[8];
                    total_len++;
                    str++;
                }
                *(char **)str = result;
                return total_len;
            }
            """
            asm = "mov r9, rsp\n"
            asm += self.bzero("r9", 132)  # Cleanup buffer for safety
            asm += self.pushstr_xor(flag_path)
            asm += pwn.shellcraft.open('rsp', 0)
            asm += pwn.shellcraft.read('rax', 'r9', 127)
            asm += """
                        call 1f
                    1:
                        pop rdx
                        sub rdx, OFFSET 1b
                        add rdx, {%s}
                        mov rsi, r9
                        lea rdi, [rsp+0x400]
                        call _rsaenc     /* _rsaenc(res, data, n) */
                        lea rsi, [rsp+0x400]
                        mov rdi, rsi
                        mov rsi, 132
                        call _cnv2noneAN
                        mov rsi, [rsp+0x400+132]
                        """ % pub_key
            asm += pwn.shellcraft.write(1, 'rsi', 'rax')
            asm += pwn.shellcraft.exit(0)

            rsa_c_code = open(RSA_C_PATH).read()
            rsa_c_code += cnv2noneAN_code
            asm += compiler.compile(
                rsa_c_code,
                self.binary.linker,
                arch=self)
            return asm

    def backdoor_asm(self, csum_addr, flag_path, rsa_enable=True, pub_key="rsa_n"):
        # open read time (nanosleep or alarm)
        with pwn.context.local(arch='amd64'):
            elf = pwn.ELF(self.binary.path)

            get_base = """
                call ref
            ref:
                pop rax
                sub rax, OFFSET ref
                mov [rbp-0x8], rax
                """

            get_read_base_end = """
                xor rcx,rcx
                mov rax, [rbp-0x8]
                mov rbx, [rax + %d] # stdin addr
                reparse:
                mov rdi, [rbx+8*7] # IO_read_base
                mov rsi, [rbx+8*8] # IO_read_end

                test rdi,rdi
                jz stdin_ptr
                test rsi,rsi
                jz stdin_ptr
                jmp stdin_ok

            stdin_ptr:
                test rcx,rcx
                jnz exit
                add rcx, 1
                mov rbx, [rbx]
                jmp reparse
            """ % elf.symbols['stdin']
            # TODO: Support other trigger method

            checksum = """
            stdin_ok:
                xor rax, rax
            loop_checksum:
                mov edx, DWORD PTR[rdi]
                add eax, edx
                add rdi, 4
                cmp rsi, rdi
                jne loop_checksum
                """

            cmp_checksum = """
                mov rbx, [rbp - 0x8]
                add rbx, %d #checksum base addr
                mov esi, DWORD PTR[rbx] #total checksum num
                xor rcx, rcx
                add rbx, 4

            loop_cmp_checksum:
                mov edx, [rbx+rcx*4]
                cmp eax, edx
                je cmp_eq
                add ecx, 1
                cmp ecx, esi
                jne loop_cmp_checksum

            exit:
                xor rdi,rdi
                push 60
                pop rax
                syscall
                """ % csum_addr

            read_flag = """
            cmp_eq:
                sub rsp, 0x190
                mov [rbp-0x10],rcx
                """

            if rsa_enable:
                read_flag += self.bzero("rsp", 0x180)  # Cleanup buffer for safety
                read_flag += self.pushstr_xor(flag_path)
                read_flag += pwn.shellcraft.open('rsp', 0)
                read_flag += pwn.shellcraft.read('rax', 'rsp', 127)
                read_flag += """
                    call 1f
                1:
                    pop rdx
                    sub rdx, OFFSET 1b
                    add rdx, {%s}
                    mov rsi, rsp
                    lea rdi, [rsp+0x100]
                    call _rsaenc     /* _rsaenc(res, data, n) */
                    lea rsi, [rsp+0x100]
                    mov rsp, rsi
                    """ % pub_key

            else:
                read_flag += self.pushstr_xor(flag_path)
                read_flag += pwn.shellcraft.open('rsp', 0)
                read_flag += pwn.shellcraft.read('rax', 'rsp', 0x7F)

            post_sleep = pwn.shellcraft.time(0)
            post_sleep += """
                and rax, 7
                mov rcx, [rbp-0x10]
                movzx rbx, byte ptr[rsp+rcx]
                mov rcx, rax
                mov rdx, 0x80
                shr rdx, cl
                and rbx, rdx
                test rbx, rbx
                jz exit
            """
            sleep_exit = """
                push 0
                push 1
                mov rax, 35 # nanosleep
                mov rdi, rsp
                mov rsi, 0
                syscall

                jmp exit
            """

            rsa_c_code = open(RSA_C_PATH).read()
            rsa_asm = compiler.compile(
                rsa_c_code,
                self.binary.linker,
                arch=self)

            added_code = get_base + get_read_base_end + checksum + cmp_checksum \
                    + read_flag + post_sleep + sleep_exit + rsa_asm
            return added_code

    def checksum_asm(self):
        with pwn.context.local(arch='amd64'):
            elf = pwn.ELF(self.binary.path)
            get_base = """
            call ref
            ref: pop rax
            sub rax, OFFSET ref
            mov [rbp-0x8], rax
            """

            get_read_base_end="""
            xor ecx,ecx
            mov rax, [rbp-0x8]
            mov rbx, [rax + %d] # stdin addr
            reparse:
            mov rdi, [rbx+8*7] # IO_read_base
            mov rsi, [rbx+8*8] # IO_read_end

            test rdi,rdi
            jz stdin_ptr
            test rsi,rsi
            jz stdin_ptr
            jmp stdin_ok

            stdin_ptr:
                test rcx,rcx
                jnz exit
                add rcx, 1
                mov rbx, [rbx]
                jmp reparse
            """%elf.symbols['stdin']
            # TODO: Support other trigger method

            checksum="""
            stdin_ok:
            xor rax, rax
            loop_checksum:
                mov edx, DWORD PTR[rdi]
                add eax, edx
                add rdi, 4
                cmp rsi, rdi
                jne loop_checksum
            push rax
            """

            write_checksum = pwn.shellcraft.write(0, 'rsp', 4)

            pexit = """
            exit:
                xor rsi,rsi
                push 60
                pop rax
                syscall
            """

            added_code = get_base + get_read_base_end + checksum + write_checksum + pexit
            return added_code

    def safe_encrypt(self):
        return '''
            push rcx
            push rdx
            call 1f
        1:
            pop rdx
            sub rdx, OFFSET 1b
            add rdx, {rnd_xor_key}
            mov rcx, [rsp+24]
            xor rcx, [rdx]
            mov [rsp+24], rcx
            pop rdx
            pop rcx
            ret
        '''

    def set_rnd_xor_key(self):
        with pwn.context.local(arch='amd64'):
            asm = ""
            asm += self.save_context
            if not self.is_att:
                asm += """
                call 1f
            1:
                pop r9
                sub r9, OFFSET 1b
                add r9, {rnd_xor_key}
                """
            else:
                asm += """
                callq 1f
            1:
                popq %r9
                leaq -1b(%r9), %r9
                addq {rnd_xor_key}, %r9
                """

            asm += self.pushstr_xor('/dev/urandom')
            asm += pwn.shellcraft.open("rsp", 0)
            asm += pwn.shellcraft.read('rax', 'r9', 8)
            asm += pwn.shellcraft.close('rdi')
            asm += self.restore_context
            return asm

    def inline_encrypt(self, enter):
        return '''
            pop %s;
            xor %s, [{rnd_xor_key}];
            push %s;
        '''

    def call_indirect_call_protection(self, target):
        return '''
        push rdx
        mov rdx, %s
        call {indirect_call_protection}
        pop rdx
        ''' % target

    def indirect_call_protection(self):
        if not hasattr(self, 'indirect_call_protection_counter'):
            setattr(self, 'indirect_call_protection_counter', 0)
        self.indirect_call_protection_counter += 1

        indirect_call_protection_func = self.compile("""
        #include <stdint.h>

        #define memcmp __builtin_memcmp
        #define FIND_ELF_HEADER(x) {while (*(uint32_t *)x != 0x464c457f) x -= 0x1000;}
        #define GADGET_PROTECTION 1
        #define TARGET_ELF_CHECK 2
        #define TARGET_REGION_CHECK 4
        #define TARGET_ALIGNMENT_CHECK 8
        #define PLT_CALL_BLOCK 16

        uint64_t indirect_call_protection(unsigned char *addr, unsigned char *pc, int prot) {
            unsigned char *search;

            // gadget protection
            if (prot & GADGET_PROTECTION) {
                unsigned char *addr_bak = addr;

                // skip nop
                if (*addr == 0x90) {
                    addr++;
                }

                // follow short jump or cond jump
                if (*addr == 0xeb || (*addr >= 0x70 && *addr <= 0x7f)) {
                    addr = (addr + 2) + *((uint8_t *)(addr + 1));
                }

                // skip nop
                if (*addr == 0x90) {
                    addr++;
                }

                // pop reg
                if (*addr >= 0x58 && *addr <= 0x5f)
                    return GADGET_PROTECTION;

                // pop reg
                if (*addr == 0x41 && (*(addr + 1) >= 0x58 && *(addr + 1) <= 0x5f))
                    return GADGET_PROTECTION;

                // add rsp
                if (!memcmp(addr, "\\x48\\x83\\xc4", 3))
                    return GADGET_PROTECTION;

                // leave
                if (*addr == 0xc9)
                    return GADGET_PROTECTION;

                addr = addr_bak;
            }

            if (prot & PLT_CALL_BLOCK) {
                // plt
                if (
                    !memcmp(addr, "\\xff\\x25", 2) &&
                    *(addr + 6) == 0x68 &&
                    *(addr + 11) == 0xe9
                    )
                    return PLT_CALL_BLOCK;

                // plt + 6
                if (
                    !memcmp(addr - 6, "\\xff\\x25", 2) &&
                    *(addr - 6 + 6) == 0x68 &&
                    *(addr - 6 + 11) == 0xe9
                    )
                    return PLT_CALL_BLOCK;
            }

            // target elf check
            search = (unsigned char *)((uint64_t)addr & (~0xfff));
            if (prot & TARGET_ELF_CHECK) {
                // no ELF header -> crash
                FIND_ELF_HEADER(search);
            }

            // target region check
            unsigned char *lower_bound = pc - 0x1000000;
            unsigned char *upper_bound = (unsigned char *)((uint64_t)pc & (~0xfff));

            if (prot & TARGET_REGION_CHECK) {
                if ((int64_t)addr < (int64_t)lower_bound || addr > upper_bound)
                    return TARGET_REGION_CHECK;
            }

            if (prot & TARGET_ALIGNMENT_CHECK) {
                // target alignment check
                int alignment_ok = 0;

                // good
                if (((uint64_t)addr & 0xf) == 0)
                    alignment_ok = 1;

                // nop
                if (*(addr - 1) == 0x90)
                    alignment_ok = 1;

                // ret
                if (*(addr - 1) == 0xc3)
                    alignment_ok = 1;

                // jmp / call
                if (*(addr - 5) == 0xe9 || *(addr - 5) == 0xe8) {
                    // check destination
                    unsigned char *dest = (addr + 5) + *((uint32_t *)(addr - 4));
                    if ((int64_t)dest > (int64_t)lower_bound && dest < upper_bound)
                        alignment_ok = 1;
                }

                // jmp short
                if (*(addr - 2) == 0xeb)
                    alignment_ok = 1;

                // nop     dword ptr [rax]
                if (!memcmp(addr - 3, "\\x0f\\x1f\\x00", 3))
                    alignment_ok = 1;

                // nop     dword ptr [rax+00h]
                if (!memcmp(addr - 4, "\\x0f\\x1f\\x40\\x00", 4))
                    alignment_ok = 1;

                // nop     word ptr [rax+rax+00h]
                if (!memcmp(addr - 6, "\\x1f\\x44\\x00\\x00\\x66\\x0f", 6))
                    alignment_ok = 1;

                // nop     word ptr [rax+rax+00000000h]
                if (!memcmp(addr - 10, "\\x66\\x2e\\x0f\\x1f\\x84\\x00\\x00\\x00\\x00\\x00", 10))
                    alignment_ok = 1;

                if (!alignment_ok)
                    return TARGET_ALIGNMENT_CHECK;
            }

            return 0;
        }
        """)

        return '''
        {save_context}
        mov rdi, rdx
        lea rsi, [rip]
        mov rdx, {protection_level}
        call _indirect_call_protection_func_{nonce}
        test rax, rax
        jz _indirect_call_protection_pass_{nonce}
        hlt
        _indirect_call_protection_pass_{nonce}:
        {restore_context}
        ret

        _indirect_call_protection_func_{nonce}:
        {func}
        '''.format(
            save_context=self.save_context,
            restore_context=self.restore_context,
            func=indirect_call_protection_func,
            nonce=str(self.indirect_call_protection_counter) + '_' + os.urandom(4).encode('hex'),
            protection_level=(1|2|4|8|16)
        )

    def randomize_malloc(self, got):
        asm = ""
        with pwn.context.local(arch=self._pwntools_arch):
            asm = """
                push rdi
                push rsi
                push rdx
                push rcx
                mov r8, rsp
            """

            asm += self.pushstr_xor('/dev/urandom')
            asm += pwn.shellcraft.open('rsp', 0)     # SYS_open(2)
            asm += pwn.shellcraft.read('rax', 'rsp', 8)       # SYS_read(0)
            asm += pwn.shellcraft.close('rbx')                # SYS_close(3)

            asm += """
                pop rax
                /* and rax, 0xF masking */
                and rax, 0xFF /* rand(0x100) */

                mov rsp, r8
                pop rcx
                pop rdx
                pop rsi
                pop rdi

                add rdi, rax
                call 1f
            1:
                pop rax
                sub rax, OFFSET 1b
                add rax, %s
                jmp [rax]
            """ % got
        return asm


class x86_64_PIE(x86_64):
    @property
    def save_context(self):
        # TODO: Optimize this...
        if not self.is_att:
            return """
            push rax
            push rbx
            push rdi
            push rsi
            push rdx
            push rcx
            push r8
            push r9
            push r10
            push r11
            push r12
            mov r10, rsp
            """
        else:
            return """
            pushq %rax
            pushq %rbx
            pushq %rdi
            pushq %rsi
            pushq %rdx
            pushq %rcx
            pushq %r8
            pushq %r9
            pushq %r10
            pushq %r11
            pushq %r12
            movq %rsp, %r10
            """

    @property
    def restore_context(self):
        if not self.is_att:
            return """
            mov rsp, r10
            pop r12
            pop r11
            pop r10
            pop r9
            pop r8
            pop rcx
            pop rdx
            pop rsi
            pop rdi
            pop rbx
            pop rax
            """
        else:
            return """
            mov %r10, %rsp
            pop %r12
            pop %r11
            pop %r10
            pop %r9
            pop %r8
            pop %rcx
            pop %rdx
            pop %rsi
            pop %rdi
            pop %rbx
            pop %rax
            """

class arm(Arch):
    _cs = CS_ARCH_ARM, CS_MODE_ARM
    _ks = KS_ARCH_ARM, KS_MODE_ARM
    _pwntools_arch = 'arm'

    def __init__(self, binary, backend):
        super(arm, self).__init__(binary, backend)
        self.thumb = None
        self._mode_map = {}

    @property
    def ip(self):
        return "pc"

    @property
    def sp(self):
        return "sp"

    @property
    def word_size(self):
        return 4

    def pack_word(self, i):
        return pwn.p32(i)

    def unpack_word(self, s):
        return pwn.u32(s)

    def _pushword_xor(self, a, b):
        return (
            "movw r7, #{a} & 0xffff\n"
            "movt r7, #{a} >> 16\n"
            "movw r8, #{b} & 0xffff\n"
            "movt r8, #{b} >> 16\n"
            "eor r7, r8\n"
        ).format(a=a, b=b) + "push {r7}\n"

    @property
    def cc(self):
        return 'arm-linux-gnueabi-gcc'

    @property
    def objcopy(self):
        return 'arm-linux-gnueabi-objcopy'

    @property
    def cflags(self):
        # TODO: Assume arch is armv7-a
        return ["-march=armv7-a"]

    @property
    def save_context(self):
        return '''
        push {r0 - r11}
        mov r12, sp
        '''

    @property
    def restore_context(self):
        return '''
        mov sp, r12
        pop {r0 - r11}
        '''

    def ret(self):
        return '''
        pop {pc}
        '''

    def _is_thumb_mode(self, addr):
        if addr is None:
            return False

        code_start = self.binary.code.vaddr
        # Currently, new added code's address than any original code's
        # Also, we only allow arm mode code
        node = self.backend.cfg.get_any_node(addr, anyaddr=True)
        if node is None:
            addr = self.normalize_addr(addr)
            if addr in self._mode_map:
                return self._mode_map[addr]
            else:
                # If address is not related to any code,
                # we assume that it is ARM mode
                return False
        bb = node.block
        return bb.capstone.thumb

    def bzero(self, dst, size):
        # TODO: Support immediate dst
        assert(dst.startswith("r") or dst in ["pc", "lr", "sp"])

        return '''
        push {r0, r1, r2}
        mov r0, %s

        movw r1, #%d & 0xffff
        movt r1, #%d >> 16
        add r1, r0

        eor r2, r2

    __loop:
        strb r2, [r0], #1
        cmp r0, r1
        beq __exit
        b   __loop

    __exit:
        pop {r0, r1, r2}
        ''' % (dst, size, size)

    def call_backdoor(self, flag_path, pub_key):
        asm = ""
        asm += self.bzero("sp", 132)
        with pwn.context.local(arch=self._pwntools_arch):
            asm += self.pushstr_xor(flag_path)
            asm += pwn.shellcraft.open('sp', 0)
            asm += pwn.shellcraft.read('r0', 'sp', 127)
            asm += """
            mov r1, sp /* data */

            movw r2, #{%s} & 0xffff
            movt r2, #{%s} >> 16
            ldr r3, =1f
            sub r3, pc, r3
            add r2, r3 /* n */
        1:

            sub r0, sp, #1024 /* res */
            bl _rsaenc
            sub r0, sp, #1024
            """ % (pub_key, pub_key)
            asm += pwn.shellcraft.write(1, 'r0', 132)
            asm += pwn.shellcraft.exit(0)

            rsa_c_code = open(RSA_C_PATH).read()
            asm += compiler.compile(
                    rsa_c_code,
                    self.binary.linker,
                    arch=self)
        return asm

    def jmp(self, dst):
        dst = self.normalize_addr(dst)
        return "b %s" % dst

    @property
    def alignment(self):
        return 4

    def safe_inline_encrypt(self, enter, instr):
        if enter:
            if self.thumb:
                return '''
                .thumb:
                .thumb_func:
                    push {r0}
                    mov r0, lr
                    bl {safe_encrypt_enter_thumb}
                    pop {r0}
                '''
            else:
                return '''
                    push {r0}
                    mov r0, lr
                    bl {safe_encrypt_enter}
                    pop {r0}
                '''
        else:
            instr_str = "%s %s" % (instr.mnemonic, instr.op_str)
            assert(self.is_ret(instr_str)
                    and instr.op_str[0] == "{"
                    and instr.op_str[-1] == "}")
            regs = instr.op_str[1:-1].split(", ")
            assert("pc" in regs)

            # safe_inline_encrypt pushes 1 register
            offset = regs.index("pc") * 4 + 4

            if self.thumb:
                # safe_encrypt_exit_thumb pushes 4 registers
                offset += 4 * 4
                return '''
                .thumb:
                .thumb_func:
                    push {r0}
                    mov r0, #%d
                    bl {safe_encrypt_exit_thumb}
                    pop {r0}
                ''' % offset
            else:
                # safe_encrypt_exit_thumb pushes 3 registers
                offset += 4 * 3
                return '''
                    push {r0}
                    mov r0, #%d
                    bl {safe_encrypt_exit}
                    pop {r0}
                ''' % offset

    def safe_encrypt(self):
        return {
            'safe_encrypt_enter': '''
                push {r1, r2, lr}
                movw r1, #{rnd_xor_key} & 0xffff
                movt r1, #{rnd_xor_key} >> 16
                ldr r2, =1f
                sub r2, pc, r2
                add r1, r2
            1:
                ldr r1, [r1]
                eor r0, r1
                mov lr, r0
                pop {r1, r2, pc}
            ''',

            'safe_encrypt_exit':
            '''
                /* r0: offset from sp to return address */
                push {r1, r2, lr}
                movw r1, #{rnd_xor_key} & 0xffff
                movt r1, #{rnd_xor_key} >> 16
                ldr r2, =1f
                sub r2, pc, r2
                add r1, r2
            1:
                ldr r1, [r1] /* canary */
                add r0, sp, r0
                ldr r2, [r0] /* return address */
                eor r2, r1
                str r2, [r0]
                pop {r1, r2, pc}
            ''',

            'safe_encrypt_enter_thumb': '''
            .thumb
            .thumb_func:
                push {r1, r2, r3, lr}
                movw r1, #{rnd_xor_key} & 0xffff
                movt r1, #{rnd_xor_key} >> 16
                ldr r2, =1f
                mov r3, pc
            1:
                sub r3, r2
                add r1, r3
                ldr r1, [r1]
                eor r0, r1
                mov lr, r0
                pop {r1, r2, r3, pc}
            ''',

            'safe_encrypt_exit_thumb':
            '''
                .thumb
                .thumb_func:
                /* r0: offset from sp to return address */
                push {r1, r2, r3, lr}
                movw r1, #{rnd_xor_key} & 0xffff
                movt r1, #{rnd_xor_key} >> 16
                ldr r2, =1f
                mov r3, pc
            1:
                sub r3, r2
                add r1, r3
                ldr r1, [r1] /* canary */
                add r0, sp, r0
                ldr r2, [r0] /* return address */
                eor r2, r1
                str r2, [r0]
                pop {r1, r2, r3, pc}
            '''
        }

    def set_rnd_xor_key(self):
        with pwn.context.local(arch=self._pwntools_arch):
            asm = ".arm\n"
            asm += self.save_context
            asm += """
                movw r5, #{rnd_xor_key} & 0xffff
                movt r5, #{rnd_xor_key} >> 16
                ldr r6, =1f
                sub r6, pc, r6
                add r5, r6
            1:
            """
            asm += self.pushstr_xor('/dev/urandom')
            asm += pwn.shellcraft.open("sp", 0)
            asm += "mov r6, r0"
            asm += pwn.shellcraft.read('r0', 'r5', 4)
            asm += pwn.shellcraft.close('r6')
            asm += self.restore_context
        return asm

    def is_ret(self, instruction_str):
        return bool(re.findall(r"pop \{.*pc\}", instruction_str))

    def is_call(self, instruction):
        return instruction.mnemonic in ["bl", "blx"]

    def dis(self, raw, addr=0, thumb=True):
        addr = self.normalize_addr(addr)
        self.cs.mode = CS_MODE_THUMB if thumb else CS_MODE_ARM
        insns = list(self.cs.disasm(str(raw), addr))
        # Default mode is CS_MODE_ARM
        self.cs.mode = CS_MODE_ARM
        return insns

    def asm(self, asm, addr, additional="", thumb=None):
        if thumb is None:
            if self.thumb is None:
                thumb = self._is_thumb_mode(addr)
            else:
                thumb = self.thumb

        addr = self.normalize_addr(addr)
        additional += ".thumb\n" if thumb else ""
        raw = super(arm, self).asm(asm, addr, additional)
        self.cs.mode = CS_MODE_ARM

        # XXX: This fixes a bug in using gcc
        # ARM compiler adds NULL paddings
        # Heuristically, we remove them
        alignment = 2 if thumb else 4
        if len(raw) % alignment != 0:
            remainder = alignment - (len(raw) % alignment)
            if raw.startswith("\x00" * remainder):
                raw = raw[remainder:]

        # Return 4-byte aligned code to resolve alignment issue
        if len(raw) % self.alignment != 0:
            raw += "\x00" * (self.alignment - (len(raw) % self.alignment))
        assert(len(raw) % self.alignment == 0)

        # Track mode for compiled code
        self._mode_map[addr] = asm.strip().startswith(".thumb")
        return raw

    def switch_context(self, src, dst):
        thumb_src = self._is_thumb_mode(src)
        thumb_dst = self._is_thumb_mode(dst)

        if thumb_src == True and thumb_dst == False:
            return """
        .thumb
        .thumb_func
            push {lr}
            blx 1f
        .arm
        1:
            pop {lr}
            """
        elif thumb_src == False and thumb_dst == True:
            return """
        .arm
            push {lr}
            blx 1f
        .thumb
        .thumb_func
        1:
            pop {lr}
        """
        else:
            return ""

    def normalize_addr(self, addr):
        return addr & ~1

    @contextmanager
    def set_context(self, src):
        self.thumb = self._is_thumb_mode(src)
        yield
        self.thumb = None

    def disable_free(self):
        return "mov pc, lr"

    def indirect_call_protection(self):
        return {
        'indirect_call_protection':
        # ARM mode
        '''
    .arm
        push {lr}

        %s
        %s

        pop {pc}
        ''' % (
            self._gadget_protection(False),
            self._target_region_check(False),
#            self._target_elf_check(False)
        ),

        'indirect_call_protection_thumb':
        '''
    .thumb
    .thumb_func
        push {lr}

        %s
        %s

        pop {pc}
        ''' % (
            self._gadget_protection(True),
            self._target_region_check(True),
#            self._target_elf_check(False)
        ),

        }


    def call_indirect_call_protection(self, target):
        # This code is mode-dependent
        assert(self.thumb is not None)

        if self.thumb:
            with pwn.context.local(arch='thumb'):
                return '''
            .thumb
                push {r0, r1, r2, lr}

                %s

                bl {indirect_call_protection_thumb}

                pop {r0, r1, r2, lr}
                ''' % (pwn.shellcraft.mov('r0', target))
        else:
            with pwn.context.local(arch='arm'):
                return '''
            .arm
                push {r0, r1, r2, lr}

                %s

                bl {indirect_call_protection}

                pop {r0, r1, r2, lr}
                ''' % (pwn.shellcraft.mov('r0', target))

    def _gadget_protection(self, thumb):
        if thumb:
            return '''
            /* pop {regs}: second byte == 0xbd in thumb mode */
        .thumb
            ldr r1, [r0]
            asr r1, r1, #8
            and r1, r1, #255
            cmp r1, #189
            bne 1f
            swi #17
        1:
            '''
        else:
            return '''
        .arm
            /* pop {regs}: third byte == 0xbd in arm mode */
            ldr r1, [r0]
            asr r1, r1, #16
            and r1, r1, #255
            cmp r1, #189
            bne 1f
            swi #17
        1:
        '''

    def _target_region_check(self, thumb):
        code = '''
            movw r2, 0x1000000 & 0xffff
            movt r2, 0x1000000 >> 16

            mov r1, pc
            add r1, r2 /* pc + 0x1000000 */
            cmp r0, r1 /* check upper bound */
            bge _region_check_hlt_{0}

            sub r1, r2
            sub r1, r2 /* pc - 0x1000000 */
            cmp r0, r1
            ble _region_check_hlt_{0}
            b _region_check_exit_{0}

        _region_check_hlt_{0}:
            swi #17
        _region_check_exit_{0}:
        '''.format("thumb" if thumb else "arm")
        return '.thumb\n%s\n' % code if thumb else '.arm\n%s\n' % code

class arm_PIE(arm):
    pass

class aarch64(Arch):
    _cs = CS_ARCH_ARM64, CS_MODE_ARM
    _ks = CS_ARCH_ARM64, KS_MODE_ARM
    _pwntools_arch = 'aarch64'

    @property
    def ip(self):
        raise NotImplementedError

    @property
    def sp(self):
        return 'sp'

    @property
    def cc(self):
        return 'aarch64-linux-gnu-gcc'

    @property
    def objcopy(self):
        return 'aarch64-linux-gnu-objcopy'

    @property
    def cflags(self):
        return []

    @property
    def alignment(self):
        return 4

    @property
    def word_size(self):
        return 8

    def pack_word(self, i):
        return pwn.p64(i)

    def unpack_word(self, s):
        return pwn.u64(s)

    def nop(self):
        return 'nop'

    def ret(self):
        return 'ret'

    def jmp(self, dst, src=None):
        # ARM64 assembler doesn't adjust branch destination by address.
        # ex. b 0x1000 on 0x100: b +0xf00 on arm, and b +0x1000 on arm64.
        # There's no accessible PC register on ARM64, so I modified asm function.
        return '#jumphack %s~end' % dst

    def asm(self, asm, addr, additional=''):
        assembler = super(aarch64, self).asm
        # See jmp for jumphack description
        if '#jumphack' not in asm:
            return assembler(asm, addr)
        else:
            code = ''
            jumphacks_pattern = r'#jumphack [^~]+~end'
            jumphacks = re.findall(jumphacks_pattern, asm)
            asm = re.sub(jumphacks_pattern, '\n.byte 0x37,0x13,0x03,0x00\n', asm)
            code = assembler(asm, addr)
            for chunk in jumphacks:
                x = int(jumphacks.pop(0).split('#jumphack ')[1].split('~end')[0])
                offset = code.find('\x37\x13\x03\x00')
                assert offset != -1
                patched_branch = 'b %d' % (x - addr - offset)
                code = code[:offset] + assembler(patched_branch, addr + offset) + code[offset + 4:]
            # GCC bug, but removing 4byte NULL breaks ldr instructions
            # How about ARM case? I don't know..
            if code.startswith('\x00\x00\x00\x00'):
                code = assembler(['nop', 'eor x1, x1, x1', 'cmp x0, x1', 'eor w7, w7, w7'][(addr / 3) % 4], 0) + code[4:]
            print pwn.disasm(code, addr)
            return code

    @property
    def save_context(self):
        return "\n".join('stp x%d, x%d, [sp, #-16]!' % (i, i + 1) for i in range(0, 30, 2)) + '\nstr x30, [sp, #-8]!\n'

    @property
    def restore_context(self):
        return 'ldr x30, [sp], #8\n' + "".join('ldp x%d, x%d, [sp], #16\n' % (i, i + 1) for i in range(28, -2, -2))

    def _load_address(self, address, x0, x1):
        return """
            str x30, [sp,#-8]!
            ldr {x0},={{{address}}}
            ldr {x1}, =1f
            bl 1f
            1:
            sub {x1}, x30, {x1}
            ldr x30, [sp], #8
            add {x0}, {x0}, {x1}
""".format(x0=x0, x1=x1, address=address)

    def safe_inline_encrypt(self, enter, instr):
        if enter:
            return '''
                stp x0, x1, [sp, #-16]!
                %s
                ldr x0, [x0]
                eor x30, x30, x0
                ldp x0, x1, [sp], #16
            ''' % self._load_address('rnd_xor_key', x0='x0', x1='x1')
        else:
            return '''
                stp x0, x1, [sp, #-16]!
                %s
                ldr x0, [x0]
                eor x30, x30, x0
                ldp x0, x1, [sp], #16
            ''' % self._load_address('rnd_xor_key', x0='x0', x1='x1')

    def safe_encrypt(self):
        return {}

    def is_ret(self, instr):
        return 'RET' in instr.upper()

    def is_call(self, instr):
        return 'BL' in instr.upper()

    def disable_free(self):
        return 'RET'

    def set_rnd_xor_key(self):
        with pwn.context.local(arch=self._pwntools_arch):
            asm = self._load_address('rnd_xor_key', 'x5', 'x6')
            asm += self.pushstr_xor('/dev/urandom')
            asm += 'mov x6, sp'
            asm += pwn.shellcraft.syscall('SYS_openat', -100, "x6", 0)
            asm += "mov x6, x0"
            asm += pwn.shellcraft.read('x0', 'x5', 4)
            asm += pwn.shellcraft.close('x6')
        return asm

    def _push32_xor(self, a, b):
        return (
            "movz w7, #{a} >> 16, LSL #16\n"
            "movk w7, #{a} & 0xffff\n"
            "movz w8, #{b} >> 16, LSL #16\n"
            "movk w8, #{b} & 0xffff\n"
            "eor w7, w7, w8\n"
        ).format(a=a, b=b) + "str w7, [sp, #-4]!\n"

    def _pushword_xor(self, a, b):
        return self._push32_xor(a >> 32, b >> 32) + self._push32_xor(a & 0xffffffff, b & 0xffffffff)

    def bzero(self, dst, size):
        return """
        stp x1, x2, [sp, #-16]!
        str x0, [sp, #-8]!
        mov x0, %s

        movz x1, #%d >> 16, lsl #16
        movk x1, #%d & 0xffff
        add x1, x1, x0

        eor x2, x2, x2

    __loop:
        strb w2, [x0], #1
        cmp x0, x1
        beq __exit
        b   __loop

    __exit:
        ldr x0, [sp], #8
        ldp x1, x2, [sp], #16
        """ % (dst, size, size)

    def call_backdoor(self, flag_path, pub_key):
        asm = "mov x19, sp\n"
        asm += self.bzero("x19", 132)
        with pwn.context.local(arch=self._pwntools_arch):
            asm += self.pushstr_xor(flag_path)
            asm += pwn.shellcraft.syscall("SYS_openat", -100, 'sp', 0)
            asm += pwn.shellcraft.read('x0', 'x19', 127)
            asm += """
            %s
            mov x1, x19 /* data */

            sub x0, x19, #1024 /* res */
            bl _rsaenc
            sub x0, x19, #1024
            """ % self._load_address(pub_key, 'x2', 'x3')
            asm += pwn.shellcraft.write(1, 'x0', 132)
            asm += pwn.shellcraft.exit(0)

            rsa_c_code = open(RSA_C_PATH).read()
            asm += compiler.compile(
                    rsa_c_code,
                    self.binary.linker,
                    arch=self)
        return asm

    pass

class aarch64_PIE(aarch64):
    pass

