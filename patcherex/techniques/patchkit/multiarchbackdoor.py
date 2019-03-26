import os

import patcherex
import angr
import pwn

import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *
from patcherex.techniques.bitflip import Bitflip
from patcherex.backends.patchkit.core import compiler
from patcherex.backends.patchkit.core.util.rsa import rsa

l = logging.getLogger("patcherex.techniques.patchkit.MultiArchBackdoor")


class MultiArchBackdoor(object):

    def __init__(self, binary_fname, backend, flag_path, addr, template):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.flag_path = flag_path
        self.addr = addr
        self.template = template

    def get_patches(self):
        patches = []
        assert('{BACKDOOR}' in self.template)
        patches.append(AddRODataPatch(rsa.raw_n(), "rsa_n"))

        code = self.patcher.arch.call_backdoor(self.flag_path, "rsa_n")
        code = self.template.replace('{BACKDOOR}', code)
        patches.append(InsertCodePatch(self.addr, code, name='backdoor'))
        return patches
