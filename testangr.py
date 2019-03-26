#!/usr/bin/env python2
import sys
import os
#import angr

from patcherex.backends.patchkitdetourbackend import PatchkitDetourBackend
from patcherex.patches import *

backend = PatchkitDetourBackend('./hello_x86')
patches = []  
calladdr = {}
#calladdr[0x400550] = 0x400400
calladdr [0x804843b] = 0x80482e0

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

jmp_addr = backend.get_current_code_position()
#second_jmp = backend.get_current_code_position() + 0x18
second_jmp = backend.get_current_code_position() + 0x1f
#patches.append(InsertCodePatch(0x400550, inject_code_64 % (calladdr[0x400550], second_jmp)))
patches.append(InsertCodePatch(0x804843b, inject_code_32 % (calladdr[0x804843b], second_jmp)))
backend.apply_patches(patches)
backend.save("/mnt/output/hello_x86_pert") 


"""
0804840b <main>:
 804840b:       8d 4c 24 04             lea    0x4(%esp),%ecx
 804840f:       83 e4 f0                and    $0xfffffff0,%esp
 8048412:       ff 71 fc                pushl  -0x4(%ecx)
 8048415:       55                      push   %ebp
 8048416:       89 e5                   mov    %esp,%ebp
 8048418:       51                      push   %ecx
 8048419:       83 ec 14                sub    $0x14,%esp
 804841c:       c7 45 f0 00 00 00 00    movl   $0x0,-0x10(%ebp)
 8048423:       8b 45 f0                mov    -0x10(%ebp),%eax
 8048426:       83 c0 01                add    $0x1,%eax
 8048429:       89 45 f4                mov    %eax,-0xc(%ebp)
 804842c:       8b 45 f4                mov    -0xc(%ebp),%eax
 804842f:       83 c0 03                add    $0x3,%eax
 8048432:       83 ec 08                sub    $0x8,%esp
 8048435:       50                      push   %eax
 8048436:       68 d0 84 04 08          push   $0x80484d0
 804843b:       e8 a0 fe ff ff          call   80482e0 <printf@plt>
 8048440:       83 c4 10                add    $0x10,%esp
 8048443:       b8 00 00 00 00          mov    $0x0,%eax
 8048448:       8b 4d fc                mov    -0x4(%ebp),%ecx
 804844b:       c9                      leave  
 804844c:       8d 61 fc                lea    -0x4(%ecx),%esp
 804844f:       c3                      ret    
"""

"""
0000000000400526 <main>:
  400526:       55                      push   %rbp
  400527:       48 89 e5                mov    %rsp,%rbp
  40052a:       48 83 ec 10             sub    $0x10,%rsp
  40052e:       c7 45 f8 00 00 00 00    movl   $0x0,-0x8(%rbp)
  400535:       8b 45 f8                mov    -0x8(%rbp),%eax
  400538:       83 c0 01                add    $0x1,%eax
  40053b:       89 45 fc                mov    %eax,-0x4(%rbp)
  40053e:       8b 45 fc                mov    -0x4(%rbp),%eax
  400541:       83 c0 03                add    $0x3,%eax
  400544:       89 c6                   mov    %eax,%esi
  400546:       bf e4 05 40 00          mov    $0x4005e4,%edi
  40054b:       b8 00 00 00 00          mov    $0x0,%eax
  400550:       e8 ab fe ff ff          callq  400400 <printf@plt>
  400555:       b8 00 00 00 00          mov    $0x0,%eax
  40055a:       c9                      leaveq 
  40055b:       c3                      retq   
  40055c:       0f 1f 40 00             nopl   0x0(%rax)
"""