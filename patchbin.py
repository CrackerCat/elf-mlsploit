#!/usr/bin/env python2

import os
import sys
import pickle
import random
import struct
import logging
import commands
import subprocess

from conf import *
from tqdm import tqdm
from functools import wraps
from patcherex.patches import *
from patcherex.backends.patchkitdetourbackend import PatchkitDetourBackend

#from pwn import *
#context.arch = 'i386'

inject_code_64 = """
push r13
mov r13, %s
call r13
pop r13
jmp %s
"""

inject_code_32 = """
mov [esp+0x100], edi
mov edi, %s
call edi
mov edi, [esp+0x100]
jmp %s
"""

def ret_arch(in_pn):
    cmd = "file %s" % in_pn
    out = commands.getoutput(cmd)

    return int(out.split("ELF ")[1].split("-bit")[0].strip())

class PatchBin(object):
    def __init__(self, in_pn, out_pn, addrfiles, limitnum):
        self.in_pn = in_pn
        self.out_pn = out_pn
        self.addrfile_pn = addrfiles     
        if limitnum == "True":
            self.limitnum = True
        else:
            self.limitnum = False

        self.calladdr = self.read_patchaddr()
        if self.limitnum == True:
            self.calladdr = dict(self.calladdr.items()[0:MAX_PATCH])

        self.addr_candidates = self.calladdr.keys()
        self.patches = []        
        self.arch = ret_arch(in_pn) 
        self.backend = PatchkitDetourBackend(self.in_pn)
        self.patches = []

    def read_patchaddr(self):
        with open(self.addrfile_pn, 'rb') as f:
            out = pickle.load(f)
            return out

    def patch_pateherex(self):
        if self.arch == 32:
            self.patch_patcherex_32()
        elif self.arch == 64:
            self.patch_patcherex_64()

    def patch_patcherex_32(self):
        for addr in tqdm(self.addr_candidates):
            second_jmp = self.backend.get_current_code_position() + 0x1f        
            self.patches.append(InsertCodePatch(int(addr,16), inject_code_32 % (self.calladdr[addr], second_jmp)))
            self.backend.apply_patches(self.patches)

        self.backend.save(self.out_pn) 
                
    def patch_patcherex_64(self):         
        for addr in tqdm(self.addr_candidates):
            second_jmp = self.backend.get_current_code_position() + 0x18        
            self.patches.append(InsertCodePatch(int(addr,16), inject_code_64 % (self.calladdr[addr], second_jmp)))
            self.backend.apply_patches(self.patches)
        self.backend.save(self.out_pn)

def main(argv):    
    in_pn = argv[1]
    out_pn = argv[2]
    addrfiles = argv[3]
    limitnum = argv[4]
    pb = PatchBin(in_pn, out_pn, addrfiles, limitnum)
    pb.patch_pateherex()

if __name__ == '__main__':
    main(sys.argv)



"""
def read_patchaddr(self):
    out = []
    with open(self.addrfile_pn, 'r') as f:
        lines = f.readlines()
        for line in lines:
            addr = line.strip()
            out.append(addr)
    return out

def patch_pwntools(self):
    os.system("rm -f %s" % self.out_pn)
    asm_emit = "nop;nop;nop;nop;nop"
    asm_code = asm(asm_emit)
    count = 0

    for addr in self.patch_addr:            
        count += 1
        addr = int(addr.replace("0x", ""), 16)
        #disasm = "DISASM", self.elf.disasm(addr, 5)
        self.elf.write(addr, asm_code)

    self.elf.save(self.out_pn)
    print "[*] Patched %d locations" % count
    #os.chmod(self.out_pn, 0755)
"""
