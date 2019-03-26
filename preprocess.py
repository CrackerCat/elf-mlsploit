#!/usr/bin/env python2
import os
import sys
import csv
import json
import time
import pickle
import commands
import executor
import operator

from executor import execute
from conf import *

def read_json(json_file, key):
  with open(json_file, 'r') as fh:
    input_dict = json.load(fh)

    return input_dict[key]

def cleanup_dirs():
    os.system("rm -rf /tmp/output/mal/")
    os.system("rm -rf /tmp/output/ben/")
    os.system("rm -rf /mnt/input/mal/")
    os.system("rm -rf /mnt/input/ben/")

def distribute_files (json_file, mal_dir, ben_dir):
    mkdirs(mal_dir)
    mkdirs(ben_dir)

    basedir = "/mnt/input"
    with open(json_file, 'r') as fh:
        input_dict = json.load(fh)
        filelist = input_dict["files"]
        tag = input_dict["tags"]#["tag_b"]

        #print input_dict["num_files"]        

        for i in xrange(len(filelist)):
            #print filelist[i], tag[i]["tag_b"]
            if tag[i]["tag_b"] == "mal":
                cmd = "cp %s %s" % (os.path.join(basedir, filelist[i]), mal_dir)
            elif tag[i]["tag_b"] == "ben":
                cmd = "cp %s %s" % (os.path.join(basedir, filelist[i]), ben_dir)
            os.system(cmd)

def mkdirs(pn):
    try:
        os.makedirs(pn)
    except OSError as e:
        pass

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
            if extract_call_name(line, ignore_indirect=True) != NONE:
                call_list.append(extract_call_name(line, ignore_indirect=True))
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

        self.outdict = {}
        self.outdict["name"] = "extract"
        #self.outdict["action"] = "transformation"
        self.result = []
        self.status = []
        self.files = []
        self.num_files = 0

        self.global_log = ""

    def log(self, msg):
        time_str = time.strftime('%X %x %Z')
        log_msg = "[%s] %s\n" % (time_str, msg) 
        print log_msg
        self.global_log += log_msg

    def dump_log(self, out_pn):
        with open(out_pn, 'w') as f:
            f.write(self.global_log)    

    def ret_index(self):
        self.pair_idx += 1
        return self.pair_idx - 1
        
    def extract_two_gram(self, call_list, save=None):
        """ store to global """
                
        for idx in xrange(len(call_list)-1):            
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
            self.log("  >>> " + str(index) + ": " + filename)
            output = _objdump_extract_calls(filename)
            call_list = extract_caller(output)
            self.extract_two_gram(call_list)
        
        sorted_dict = sorted(self.pair_count.items(), key=operator.itemgetter(1)) 
        pair_to_count_temp = dict(sorted_dict[-NUM_DICT:])
        out = {}
        for i, pair in enumerate(pair_to_count_temp.keys()):
            out[pair] = i
        
        with open(save, 'wb') as handle:
            pickle.dump(out, handle, protocol=pickle.HIGHEST_PROTOCOL)

    def load_model(self, in_pn):        
        with open(in_pn, 'rb') as f:
            pickle_obj = pickle.load(f)            
            self.pair_index = pickle_obj["two-gram"]
            self.pair_idx = len(self.pair_index)

    def load_pair_count(self):        
        with open(DICT_NAME, 'rb') as handle:
            self.pair_index = pickle.load(handle)

        self.pair_idx = len(self.pair_index)

    def build_feature_csv(self, target_dir, savename, follow_imp=False, normalize=True):
        filelist = load_filelist_from_dir(target_dir, onlyfile=False)

        for index, filename in enumerate(filelist):
            self.log("  >>> " + str(index) + ": "+ filename)
            output = _objdump_extract_calls(filename)            
            call_list = extract_caller(output)
            two_gram_list = self.two_gram_to_count(call_list, follow_impl=follow_imp)
            if normalize:
                norm_list = normalize_list(two_gram_list)  # two_gram_list [idx]:count
            else:
                norm_list = two_gram_list

            savename = os.path.join("/mnt", "output", savename)

            with open(savename, "a") as fp:
                wr = csv.writer(fp, dialect='excel')
                wr.writerow(norm_list)

    def build_feature_csv_indv(self, target_dir, kind, follow_imp=False, normalize=True):
        filelist = load_filelist_from_dir(target_dir, onlyfile=False)

        for index, filename in enumerate(filelist):
            self.log("  >>> " +  str(index) + ": " +  filename)
            output = _objdump_extract_calls(filename)            
            call_list = extract_caller(output)
            two_gram_list = self.two_gram_to_count(call_list, follow_impl=follow_imp)
            if normalize:
                norm_list = normalize_list(two_gram_list)  # two_gram_list [idx]:count
            else:
                norm_list = two_gram_list
            
            #pn = kind+str(index)+".csv"
            pn = os.path.basename(filename)+".csv"
            #pn = os.path.join("/mnt", "output", pn)
            mkdirs("/tmp/output/malcsv")
            mkdirs("/tmp/output/bencsv")
            pn = os.path.join("/tmp", "output", "%scsv" % kind, pn)

            with open(pn, "w") as fp:
                wr = csv.writer(fp, dialect='excel')
                wr.writerow(norm_list)

            self.files.append(os.path.basename(filename))
            tag_dict = {"tag_a":os.path.getsize(pn), "tag_b":kind}
            self.result.append(tag_dict)
            if os.path.getsize(pn) > 0:
                self.status.append("success")
            else:
                self.status.append("fail")

    def dump_json(self, out_pn):
        self.outdict["result"] = self.result
        self.outdict["files"] = self.files
        self.outdict["status"] = self.status
        self.outdict["num_files"] = len(self.files)
        
        with open(out_pn, 'w') as f:
            f.write(json.dumps(self.outdict))

def main():
    # action: transformation
    # name: extract
    # model: null

    mal_dir = "/tmp/output/mal"
    ben_dir = "/tmp/output/ben"
    output_global_log = "/mnt/output/log.txt"

    # process file in pre-destination
    cleanup_dirs()
    os.system("rm -rf /tmp/output")
    mkdirs("/tmp/output")
    mkdirs("/tmp/output/mal")
    mkdirs("/tmp/output/ben")
    distribute_files ("/mnt/input/input.json", mal_dir, ben_dir)
    
    ft = Feature(mal_dir, ben_dir)

    # is two_gram file not exist 
    input_json = "/mnt/input/input.json"
    #action = str(read_json(input_json, "action"))
    name = str(read_json(input_json, "name"))
    model_file = str(read_json(input_json, "model"))

    #if not os.path.exists(DICT_NAME):
    if name == "tra":
        ft.log( "[*] collect two-gram pairs")
        ft.collect_pair_list(DICT_NAME, NUM_DICT)
        ft.load_pair_count()
    else:        
        ft.log("[*] processing input files")
        ft.load_model(os.path.join("/mnt", "input", model_file))
    
    
    # generage csv files
    ft.build_feature_csv_indv(mal_dir, "mal", follow_imp=True, normalize=False)
    ft.build_feature_csv_indv(ben_dir, "ben", follow_imp=True, normalize=False)
    ft.dump_log(output_global_log)
    cleanup_dirs()

    # we don't need to generate json
    #ft.dump_json("/mnt/output/output.json")

if __name__ == "__main__":
    main()