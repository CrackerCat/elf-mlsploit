import sys
import logging

import nose
from rsa import *

l = logging.getLogger('patcherex.backends.patchkit.core.util.rsa')

def test_c():
    encrypted = commands.getoutput("./test_c")
    nose.tools.ok_(decrypt(encrypted) == "Hello World")

def test_x86():
    encrypted = commands.getoutput("./test_x86")
    nose.tools.ok_(decrypt(encrypted) == "Hello World")

def test_x64():
    encrypted = commands.getoutput("./test_x64")
    nose.tools.ok_(decrypt(encrypted) == "Hello World")

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            l.info("testing %s" % str(f))
            all_functions[f]()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
