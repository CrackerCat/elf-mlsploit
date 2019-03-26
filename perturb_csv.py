#!/usr/bin/env python2
import os
import sys
import csv
import pickle
import pandas as pd

# JJ: this is file for testing perturbation 

"""
input: 
  csv (.csv)
  pickle file
output: csv (_perturb.csv)

NOTE
1) we should re-normalize 
2) only allow injection
3) inject with api-name?
4) inject with index? (OK)
"""

def usage():
    print "python perturb_csv.py csv_file two-gram.pkl"
    print "e.g., python perturb_csv.py processed/indiv/benign0.csv processed/two_gram/two_gram_mini.pkl"

def set_to_dict(_set):
    out = {}
    for i, item in enumerate(_set):
        trans = item[0]
        count = item[1]
        out[trans] = i
    return out

class Perturb(object):
    def __init__(self, csv_pn, pickle_pn=None):
        self.csv_pn = csv_pn
        self.sample_values = self.load_csv()

        # if we want to support "inject by api-to-api name"        
        if pickle_pn is not None:
            self.pair_to_index = pickle.load( open(self.pickle_pn,'rb'))

        print self.sample_values

    def load_csv(self):
        out = []
        with open(self.csv_pn, 'r') as f:
            data = f.read()
            items = [int(x.strip()) for x in data.split(",")]
            for item in items:
                out.append(item)
        return out

    def ret_index(self, prev_api, next_api):
        two_gram = "%s|%s" % (prev_api, next_api)
        if two_gram in self.pair_to_index.keys():
            return self.pair_to_index[two_gram]
        else:
            return -1
        
    def ret_transition(self, index):
        for two_gram, count in self.pair_to_index.items():
            if count == index:
                return two_gram
        return "NONE"

    def perturb(self, index):
        self.sample_values[index] += 1        

    def store(self, outpn):
        with open(outpn, "w") as fp:
            wr = csv.writer(fp, dialect='excel')
            wr.writerow(self.sample_values)

def main():    
    if len(sys.argv) < 2:
        usage()

    else: 
        csv_pn = sys.argv[1]
        pickle_pn = sys.argv[2]

        pt = Perturb(csv_pn, pickle_pn=None)
        #pt.perturb(3000)        
        #pt.perturb(2999)
        pt.store("/tmp/perturb.csv")

if __name__ == "__main__":
    main()
