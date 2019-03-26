from idautils import *
from idaapi import *
import idc
import tempfile
import sys

autoWait()

if len(sys.argv) >= 2:
     filename = sys.argv[1]    
else:
     _, filename = tempfile.mkstemp()

ea = ScreenEA()
fp = open(filename, 'w')

# Loop through all the functions
for function_ea in Functions(SegStart(ea), SegEnd(ea)):
    # Print the address and the function name.
    print hex(function_ea), GetFunctionName(function_ea)
    fp.write(str(function_ea))

fp.close()
idc.Exit(0)