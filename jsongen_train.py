#!/usr/bin/env python3
import os
import sys
import json
import glob
import random

def usage():
    print "python json_generator.py raw_samples transformation extract null mamadroid"

def ret_tag(filelist):
    out = []
    for filename in filelist:
        tempdict = {}
        tempdict["tag_a"] = os.path.basename(filename)
        if "mal" in filename.lower():
            tempdict["tag_b"] = "mal"
        elif "ben" in filename.lower():
            tempdict["tag_b"] = "ben"
        else:
            tempdict["tag_b"] = "unknown"
        
        out.append(tempdict)

    return out

def ret_filelist(sample_dir):
    out = []
    filelist = glob.glob(sample_dir+"/*/*")
    for filename in filelist:
        basename = os.path.basename(filename)
        out.append(basename)
    return out

def ret_filelist_path(sample_dir):
    out = []
    filelist = glob.glob(sample_dir+"/*/*")
    for filename in filelist:    
        out.append(filename)
    return out

def ret_option(option):
    out = {}
    counter = 0
    if "-" in option:
        options = option.split("-")
        for opt in options:
            out["option%d" % counter] = opt.strip()
            counter += 1
    else:
        out = {"option1":"null", "option2":"null"}
    return out

class MakeJson(object):
    def __init__(self, sample_dir, action, name, option, model):
        self.sample_dir = sample_dir
        self.action = action
        self.name = name
        self.option = ret_option(option)
        self.model =  model

        self.filelist = ret_filelist(self.sample_dir)
        self.filelist_path = ret_filelist_path(self.sample_dir)
        self.outdict = {}
        self.tags = []

    def generate_json(self):
        self.outdict["action"] = self.action
        self.outdict["name"] = self.name
        self.outdict["num_files"] = len(self.filelist)
        self.outdict["files"] = self.filelist
        self.outdict["option"] = ret_option(self.option)
        self.outdict["tags"] = ret_tag(self.filelist_path)
        self.outdict["model"] = self.model

    def save_json(self, out_pn):
        with open(out_pn, 'w') as f:
            f.write(json.dumps(self.outdict))

def main():
    if len(sys.argv) < 1:
        usage()

    else:
        sample_dir = sys.argv[1]  # user-specified
        action     = "train"  # transformation, train, evaluation
        name       = "train"  # user-specified (custom name)
        option     = "null-null"  # user-specified
        model      = "nn.pkl"  # user-specified (model name)

        mj = MakeJson(sample_dir, action, name, option, model)
        mj.generate_json()
        mj.save_json("input.json")

if __name__ == "__main__":
    main()