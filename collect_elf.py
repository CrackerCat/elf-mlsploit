import magic
import os
import random

def load_filelist_from_dir(dirname, onlyfile = True):
  "Get all files end without extension in directory"
  extension_path = []
  for root, dirs, files in os.walk(dirname):
    for filename in files:
      if onlyfile:
        extension_path.append(filename)
      else:
        extension_path.append(root + "/" + filename)
  return extension_path

def ret_magic(filename):
  magic_value = magic.from_file(filename)
  return magic_value

def cp_elf_to_dst(dirname1):

  for src in SRC:
    filelist = load_filelist_from_dir(src, onlyfile = False)
    #print dirname
    #print filelist

    for filename in filelist:
      if os.path.islink(filename) == True:
        continue

      mg = ret_magic(filename).lower()    

      if "elf" in mg and ret_size(filename) < SIZE_MAX:      
        os.system("cp %s %s" % (filename, dirname1))

def ret_size(filename):
  return os.path.getsize(filename)


SRC = ["/bin", "/usr/bin", "/usr/local/bin", "/usr/lib64/", "/usr/local/lib/"]
DST1 = "/tmp/dst1"

SIZE_MAX = 1000000

#filelist = load_filelist_from_dir(SRC, onlyfile = False)
cp_elf_to_dst(DST1)
