#!/usr/bin/env python2
import os
import sys
import commands
import executor
import pickle
import csv
import operator

from executor import execute
from conf import *

# stored pkl file? pair_to_index (3000 most)
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

def extract_caller(objdump):
    call_list = []
    for line in objdump.split("\n"):    
        if line != "":
            if extract_call_name(line) != NONE:
                call_list.append(extract_call_name(line))
    return call_list

def _objdump_extract_calls(filename):
    ret = ""

    cmd = 'objdump -d %s' % filename
    output =  commands.getoutput(cmd)
    #output = execute(cmd, capture=True)    

    for line in output.split("\n"):                
        if "call" in line:
            ret += line + "\n"
    return ret

def extract_call_name(line):
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

def normalize_list(_list):
    out_list = []
    _sum = sum(_list)

    for idx in xrange(len(_list)):
        if _list[idx] == 0:
            out_list.append(float(0))
        else:
            #out_list.append( round(float(_list[idx])/_sum, 5))            
            otemp = "%.6f" % (float(_list[idx])/ _sum)            
            out_list.append(otemp)

    return out_list

class Feature(object):
    def __init__(self, mal_pn, ben_pn):
        self.pair_count = {}
        self.pair_index = {}
        self.pair_idx  = 0
        self.mal_pn = mal_pn
        self.ben_pn = ben_pn

    def ret_index(self):
        self.pair_idx += 1
        return self.pair_idx - 1
        
    def extract_two_gram(self, call_list, save=None):
        """ store to global """
                
        for idx in xrange(len(call_list)-1):
            #print call_list[idx]
            #print call_list[idx+1]
            current_two_gram = call_list[idx]+"|"+call_list[idx+1]
            if current_two_gram not in self.pair_count.keys():
                self.pair_count[current_two_gram] = 1                
                self.pair_index[current_two_gram] = self.ret_index()
            else:
                self.pair_count[current_two_gram] +=1
                self.pair_index[current_two_gram] = self.ret_index()

    def two_gram_to_count(self, call_list, follow_impl=False):
       
        out_count_list = [0] * (len(self.pair_index) +1)
        keys = self.pair_index.keys()

        for idx in xrange(len(call_list)-1):
            current_two_gram = call_list[idx]+"|"+call_list[idx+1]
            if current_two_gram in keys:
                two_gram_idx = self.pair_index[current_two_gram]
            else:
                two_gram_idx = len(out_count_list) -1

            if not follow_impl:
                out_count_list[two_gram_idx] = 1
            else:
                out_count_list[two_gram_idx] += 1
        return out_count_list

    def collect_pair_list(self, save, number):

        collection_of_dict = []

        mal_list = load_filelist_from_dir(self.mal_pn, onlyfile=False)
        ben_list = load_filelist_from_dir(self.ben_pn, onlyfile=False)

        sampling = 1.0
        mal_list = mal_list[0:int(len(mal_list)*sampling)]
        ben_list = ben_list[0:int(len(ben_list)*sampling)]
        all_list = mal_list + ben_list

        for index, filename in enumerate(all_list):
            print index, filename
            output = _objdump_extract_calls(filename)
            call_list = extract_caller(output)
            self.extract_two_gram(call_list)
        
        sorted_dict = sorted(self.pair_count.items(), key=operator.itemgetter(1))        
        #print pair ==> count
        pair_to_count_temp = dict(sorted_dict[-NUM_DICT:])
        out = {}
        for i, pair in enumerate(pair_to_count_temp.keys()):
            out[pair] = i
        
        with open(save, 'wb') as handle:
            pickle.dump(out, handle, protocol=pickle.HIGHEST_PROTOCOL)

    def load_pair_count(self):        
        with open(DICT_NAME, 'rb') as handle:
            self.pair_index = pickle.load(handle)

        self.pair_idx = len(self.pair_index)

    def build_feature_csv(self, target_dir, savename, follow_imp=False, normalize=True):
        filelist = load_filelist_from_dir(target_dir, onlyfile=False)

        for index, filename in enumerate(filelist):
            print index, filename
            output = _objdump_extract_calls(filename)            
            call_list = extract_caller(output)
            two_gram_list = self.two_gram_to_count(call_list, follow_impl=follow_imp)
            if normalize:
                norm_list = normalize_list(two_gram_list)  # two_gram_list [idx]:count
            else:
                norm_list = two_gram_list

            with open(savename, "a") as fp:
                wr = csv.writer(fp, dialect='excel')
                wr.writerow(norm_list)

    def build_feature_csv_indv(self, target_dir, kind, follow_imp=False, normalize=True):
        filelist = load_filelist_from_dir(target_dir, onlyfile=False)

        for index, filename in enumerate(filelist):
            print index, filename
            output = _objdump_extract_calls(filename)            
            call_list = extract_caller(output)
            two_gram_list = self.two_gram_to_count(call_list, follow_impl=follow_imp)
            if normalize:
                norm_list = normalize_list(two_gram_list)  # two_gram_list [idx]:count
            else:
                norm_list = two_gram_list
            
            pn = kind+str(index)+".csv"            
            with open(pn, "w") as fp:
                wr = csv.writer(fp, dialect='excel')
                wr.writerow(norm_list)                  

def main():
    mal_dir = sys.argv[1]
    ben_dir = sys.argv[2]
    
    ft = Feature(mal_dir, ben_dir)

    # is two_gram file not exist    
    if not os.path.exists(DICT_NAME):
        ft.collect_pair_list(DICT_NAME, NUM_DICT)
    
    # normal load
    ft.load_pair_count()
    
    # generage csv files
    ft.build_feature_csv_indv(mal_dir, "mal", follow_imp=True, normalize=False)
    ft.build_feature_csv_indv(ben_dir, "ben", follow_imp=True, normalize=False)

if __name__ == "__main__":
    main()