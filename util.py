#import commands
import subprocess

def _objdump_extract_calls(filename):
    ret = ""

    cmd = 'objdump -d %s' % filename
    #output =  commands.getoutput(cmd)    
    #output = execute(cmd, capture=True)
    output = subprocess.getoutput(cmd)

    for line in output.split("\n"):                
        if "call" in line:
            ret += line + "\n"
    return ret

def extract_call_name(line, ignore_indirect=False):
    #print line
    split = ""
    if 'callq ' in line:
        split = "callq"
    elif 'call ' in line:
        split = "call"
    else:
        return NONE

    first_chunk = line.split(split)[1].strip()

    if "%" in first_chunk:
        if ignore_indirect:
            return NONE
        else:
            return INDIRECT

    elif "<" in first_chunk:
        out = first_chunk.split("<")[1].split(">")[0].strip()
        if "+" in out:            
            out = out.split("+")[0]
            if "@" in out:
                return out.split("@")[0]
            return out
        elif "-" in out:            
            out = out.split("-")[0]
            if "@" in out:
                return out.split("@")[0]
            return out
        elif "@" not in out:
            return out    
        else:
            return out.split("@")[0]    

    # just referenced by address
    elif "0x" in first_chunk:
        return ADDR
    else:
        return NONE

def extract_caller(objdump):
    call_list = []
    for line in objdump.split("\n"):    
        if line != "":
            if extract_call_name(line, ignore_indirect=True) != NONE:
                call_list.append(extract_call_name(line, ignore_indirect=True))
    return call_list