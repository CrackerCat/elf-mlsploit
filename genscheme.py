#!/usr/bin/env python2

import os
import sys
import json


def ret_default_dict (action):
    _dict = {}
    #_dict["action"] = action   

    return _dict

def ret_option_dict (name, type, required):
    _dict = {}
    _dict["name"] = name
    _dict["type"] = type    
    _dict["required"] = required

    return _dict

def ret_func_dict (name, tags, option, mtype=None, ftype=None):
    _dict = {}
    _dict ["name"] = name
    if option != None:
        _dict["option"] = option
    else:
        _dict["option"] = []        

    if tags != None:
        _dict["option_tags"] = tags
    _dict["mtype"] = mtype
    _dict["ftype"] = ftype
    return _dict

# for output scheme
def ret_func_dict_out (name, tags, option, mtype=None, ftype=None):
    _dict = {}
    _dict ["name"] = name
    
    if tags != None:
        _dict["option_tags"] = tags
    #_dict["mtype"] = mtype
    #_dict["ftype"] = ftype
    return _dict

def ret_tag(name1, name2, name3):
    _dict = {}
    _dict["tag_name"] = name1
    _dict["type"] = name2
    #_dict["required"] = name3
    return _dict

class GenerateScheme(object):
    def __init__(self):
        self.in_scheme = []
        self.out_scheme = []
        self.in_scheme_file = "input.schema"
        self.out_scheme_file = "output.schema"

    def gen_input(self):
        # train       
        current = ret_default_dict("train")        
        tags = []
        funcs = []
        options = []
        tags.append(ret_tag("tag_a", "str", False))
        tags.append(ret_tag("tag_b", "str", True)) 
        options.append(ret_option_dict ("algorithm", "str", True) )
        options.append(ret_option_dict ("option2", "str", False) )
        func1 = ret_func_dict("tra", tags=None, option=options, mtype="pkl")
        funcs.append(func1)
        
        #current["model"] = "nn.pkl"
        #self.in_scheme.append(current)

        # evaluation
        current = ret_default_dict("evaluation")
        tags = []
        #funcs = []
        tags.append(ret_tag("tag_a", "str", False))
        tags.append(ret_tag("tag_b", "str", True))        
        func1 = ret_func_dict("cla", tags=None, option=None, mtype="pkl")   
        funcs.append(func1)
        #current["function"] = funcs
        #current["model"] = "nn.pkl"
        #self.in_scheme.append(current)

        # transformation
        current = ret_default_dict("transformation")
        tags = []
        #funcs = []
        tags.append(ret_tag("tag_a", "str", False))
        tags.append(ret_tag("tag_b", "str", True))        
        func1 = ret_func_dict("rmapi", tags=None, option=None, mtype="pkl")   
        func2 = ret_func_dict("injectapi", tags=None, option=None, mtype="pkl")
        funcs.append(func1)
        funcs.append(func2)
        
        #current["model"] = "nn.pkl"
        current["function"] = funcs
        self.in_scheme.append(current)

    def gen_output(self):
        # train       
        current = ret_default_dict("train")        
        tags = []
        funcs = []
        options = []
        tags.append(ret_tag("tag_a", "str", False))
        tags.append(ret_tag("tag_b", "str", True))         
        func1 = ret_func_dict_out("tra", tags=tags, option=None)   
        funcs.append(func1)
        #current["function"] = funcs
        #current["model"] = "nn.pkl"
        #self.out_scheme.append(current)

        # evaluation
        current = ret_default_dict("evaluation")
        tags = []
        #funcs = []
        tags.append(ret_tag("tag_a", "str", False))
        tags.append(ret_tag("tag_b", "str", True))        
        func1 = ret_func_dict_out("cla", tags=tags, option=None)   
        funcs.append(func1)
        #current["function"] = funcs
        #current["model"] = "nn.pkl"
        #self.out_scheme.append(current)

        # transformation
        current = ret_default_dict("transformation")
        tags = []
        #funcs = []
        tags.append(ret_tag("tag_a", "str", False))
        tags.append(ret_tag("tag_b", "str", True))        
        func1 = ret_func_dict_out("rmapi", tags=tags, option=None)   
        func2 = ret_func_dict_out("injectapi", tags=tags, option=None)   
        funcs.append(func1)
        funcs.append(func2)
        
        #current["model"] = "nn.pkl"
        current["function"] = funcs
        self.out_scheme.append(current)

    def dump_json(self):
        
        with open(self.in_scheme_file, 'w') as f:
            f.write(json.dumps(self.in_scheme[0], sort_keys=True, indent=4,separators=(',', ': ')))

        with open(self.out_scheme_file, 'w') as f:
            f.write(json.dumps(self.out_scheme[0], sort_keys=True, indent=4,separators=(',', ': ')))

def main():
    gs = GenerateScheme()
    gs.gen_input()
    gs.gen_output()
    gs.dump_json()

if __name__ == "__main__":
    main()

"""
train
input {"tag_a": "avahi-set-host-name", "tag_b": "ben"}
output {"files": ["nn.pkl"], "status": ["success"], "name": "train", "num_files": 1, "result": [{"tag_a": "nn classifier"}], "action": "train"}

evaluation
input

{"files": ["VirusShare_f26c70be779bc16d240cbd3285e085f6", "VirusShare_f868057d8cf192ea9caab1f15d80ce0a", "VirusShare_f6c73f3aaff81872044dbdd5101f69fb", "VirusShare_fa1d1861e29d664b8bc381640ad40e9f", "VirusShare_fb17bd240b20489a92255b5230def3c0", "aplay", "avahi-set-host-name", "at", "apt"], "name": "classification", "tags": [{"tag_a": "VirusShare_f26c70be779bc16d240cbd3285e085f6", "tag_b": "mal"}, {"tag_a": "VirusShare_f868057d8cf192ea9caab1f15d80ce0a", "tag_b": "mal"}, {"tag_a": "VirusShare_f6c73f3aaff81872044dbdd5101f69fb", "tag_b": "mal"}, {"tag_a": "VirusShare_fa1d1861e29d664b8bc381640ad40e9f", "tag_b": "mal"}, {"tag_a": "VirusShare_fb17bd240b20489a92255b5230def3c0", "tag_b": "mal"}, {"tag_a": "aplay", "tag_b": "ben"}, {"tag_a": "avahi-set-host-name", "tag_b": "ben"}, {"tag_a": "at", "tag_b": "ben"}, {"tag_a": "apt", "tag_b": "ben"}], "num_files": 9, "action": "evaluation", "model": "nn.pkl", "option": {"option2": "null", "option1": "null"}}

output
{"files": ["VirusShare_f26c70be779bc16d240cbd3285e085f6", "VirusShare_f868057d8cf192ea9caab1f15d80ce0a", "VirusShare_f6c73f3aaff81872044dbdd5101f69fb", "VirusShare_fa1d1861e29d664b8bc381640ad40e9f", "VirusShare_fb17bd240b20489a92255b5230def3c0", "aplay", "avahi-set-host-name", "at", "apt"], "status": ["correct", "correct", "correct", "correct", "correct", "correct", "correct", "correct", "correct"], "name": "classification", "num_files": 9, "result": [{"tag_a": "mal", "tag_b": "mal"}, {"tag_a": "mal", "tag_b": "mal"}, {"tag_a": "mal", "tag_b": "mal"}, {"tag_a": "mal", "tag_b": "mal"}, {"tag_a": "mal", "tag_b": "mal"}, {"tag_a": "ben", "tag_b": "ben"}, {"tag_a": "ben", "tag_b": "ben"}, {"tag_a": "ben", "tag_b": "ben"}, {"tag_a": "ben", "tag_b": "ben"}], "action": "evaluation"}


transformation
input
{"files": ["VirusShare_f26c70be779bc16d240cbd3285e085f6", "VirusShare_fa1d1861e29d664b8bc381640ad40e9f"], "name": "rmapi", "tags": [{"tag_a": "VirusShare_f26c70be779bc16d240cbd3285e085f6", "tag_b": "mal"}, {"tag_a": "VirusShare_fa1d1861e29d664b8bc381640ad40e9f", "tag_b": "mal"}], "num_files": 2, "action": "transformation", "model": "nn.pkl", "option": {"option2": "null", "option1": "null"}}

output
{"files": ["VirusShare_f26c70be779bc16d240cbd3285e085f6", "VirusShare_fa1d1861e29d664b8bc381640ad40e9f"], "status": ["success", "success"], "name": "rmapi", "num_files": 2, "result": [{"tag_a": "VirusShare_f26c70be779bc16d240cbd3285e085f6", "tag_b": 271148}, {"tag_a": "VirusShare_fa1d1861e29d664b8bc381640ad40e9f", "tag_b": 684780}], "action": "transformation"}

"""