#!/usr/bin/env python2
import sys
import glob
import json
import pickle
import argparse
import commands
import operator
import numpy as np
import pandas as pd

# required model
from sklearn import svm
from sklearn import neighbors, metrics, preprocessing 
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF

# required aux funcs
from sklearn import cross_validation, grid_search
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.externals import joblib

# import custom files
from conf import *

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

def extract_caller(objdump):
    call_list = []
    addr_list = []
    for line in objdump.split("\n"):    
        if line != "":
            if extract_call_name(line, ignore_indirect=True) != NONE:
                call_list.append(extract_call_name(line, ignore_indirect=True))
                addr_list.append(line.split(":")[0])
    return call_list, addr_list

def read_json(json_file, key):
  with open(json_file, 'r') as fh:
    input_dict = json.load(fh)

    return input_dict[key]

def distribute_files (json_file, mal_dir, ben_dir):
  mkdirs(mal_dir)
  mkdirs(ben_dir)

  basedir = "/mnt/input"
  with open(json_file, 'r') as fh:
    input_dict = json.load(fh)
    filelist = input_dict["files"]
    tag = input_dict["tags"]#["tag_b"]

    for i in xrange(len(filelist)):
      #print filelist[i], tag[i]["tag_b"]
      if tag[i]["tag_b"] == "mal":
        cmd = "cp %s %s" % (os.path.join(basedir, filelist[i]), mal_dir)
      elif tag[i]["tag_b"] == "ben":
        cmd = "cp %s %s" % (os.path.join(basedir, filelist[i]), ben_dir)            
      os.system(cmd)

def ret_twogram_from_idx(two_gram, idx):
  for val, key in two_gram.items():
    if key == idx:
      return val

def normalize_list(_list):
  out_list = []
  _sum = sum(_list)

  for idx in xrange(len(_list)):
    if _list[idx] == 0:
      out_list.append(float(0))
    else:
      otemp = "%.6f" % (float(_list[idx])/ _sum)            
      out_list.append(otemp)

  return out_list

def mkdirs(pn):
  try:
    os.makedirs(pn)
  except OSError as e:
    pass

def integrate_csvs(filelist, target):
  with open(target, 'a') as f:
    for filename in filelist:
      with open(filename, 'r') as f2:
        data = f2.read()
        f.write(data)

#dump_addr(patch_candidate, PATCH_ADDR_FILE)
def dump_addr(cand_dict, pn):
  os.system("rm -f %s" % pn)
  with open(pn, 'w') as f:
    for val in cand_dict.keys():
      f.write("0x%s\n" % val.strip())

def ret_tpr(cm):
  tp = float(cm[0][0])
  fp = float(cm[0][1])
  fn = float(cm[1][0])
  tn = float(cm[1][1])  

  tpr = tp / (tp+fn)
  return tpr

def load_filelist_from_dir(dirname, onlyfile = True):
  extension_path = []

  for root, dirs, files in os.walk(dirname):
    for filename in files:
      if onlyfile:
        extension_path.append(filename)
      else:
        extension_path.append(root + "/" + filename)
  return extension_path

def patch_bin(in_pn, out_pn, PATCH_ADDR_FILE):
  print "checking the addr file"
  os.system("ls -al %s" % PATCH_ADDR_FILE)
  cmd = "python patchbin.py %s %s %s" % (in_pn, out_pn, PATCH_ADDR_FILE)
  os.system(cmd)

def get_highest_diff_feature(minimum, target):
  max = 0
  max_idx = 0
  max_diff = 0
  for i in xrange(len(minimum)):
    diff = minimum[i] - target[i]

    if abs(diff) > max:
      max_idx = i
      max_diff = diff
      max = abs(max_diff)
    
  return max_idx, max_diff

# we want to remove api to bypass the original classifier
# target[i] > minimum[i]
def get_highest_negdiff_feature(minimum, target, number):
  max = 0
  max_idx = 0
  max_diff = 0

  out = {}
  for i in xrange(len(minimum)):
    diff = target[i] - minimum[i]

    if diff > 0:
      out[i] = diff

    if diff > max:
      max_idx = i
      max_diff = diff
      max = diff      
    
  sorted_dict = sorted(out.items(), key=operator.itemgetter(1), reverse=True) 
  #pair_to_count_temp = dict(sorted_dict[-number:])
  pair_to_count_temp = sorted_dict
  return pair_to_count_temp


def comp_two_arrays(arr1, arr2):
  for i in xrange(len(arr1)):
    if arr1[i] != arr2[i]:
      print "%dth index diff: %d, %d" % (i, arr1[i], arr2[i])

def ret_distance(benign_set, target):
  benign_arr = benign_set
  benign_arr_len = len(benign_arr)
  target_arr = target

  min_value = 100
  min_idx = 0

  distance = np.linalg.norm(benign_arr-target_arr)    
  
  return distance

def find_closest_benign(benign_set, target):
  """
  1. find one benign file, input data is dataframe(pd)
  2. return N-th array whose distance is cloest
  """
  benign_arr = benign_set.values
  benign_arr_len = len(benign_arr)
  target_arr = target

  min_value = 100
  min_idx = 0

  for idx in range(benign_arr_len):
    distance = np.linalg.norm(benign_arr[idx]-target_arr)
    if distance < min_value:
      min_value = distance
      min_idx = idx

  return benign_arr[min_idx]

def load_csv_files(dirname, kind, sample=False):   
  files = glob.glob(dirname+"/%s/*" % kind)
  if not sample:
    csv_tmp = os.path.join("/tmp", "%s.csv" % kind)
  else:
    csv_tmp = os.path.join("/tmp", "sample.csv")

  remove_file(csv_tmp)  
  integrate_csvs(files, csv_tmp)

  return pd.read_csv(csv_tmp, header=None, engine='python')
  
def remove_file(file1):    
  os.system("rm -f %s" % file1)

class Classifier(object):
  def __init__(self, sample_dir, crossval=False, action="", name="", model=""):
    self.sample_dir = sample_dir
    self.ben_train_pd = None
    self.mal_train_pd = None
    self.all_train_pd = None
    self.groundtruth_tr_pd_pd = None
    self.clf = None
    self.two_gram = None
    self.crossval = crossval    

    self.action = action
    self.name = name
    self.model = model

    self.outdict = {}
    self.outdict["name"] = name
    self.outdict["action"] = action
    self.result = []
    self.status = []
    self.files = []
    self.num_files = 0

    if self.action != "transformation":
      self.load_groundtruth()

  def classify_one(self, in_pn):    

    #current_sample_pd = pd.DataFrame.from_csv(in_pn, engine='python')
    current_sample_pd = pd.read_csv(in_pn, header=None, engine='python')

    result = self.clf.predict(current_sample_pd)[0]
    if result == 1:
      return "ben", current_sample_pd
    elif result == 0:
      return "mal", current_sample_pd

  def dump_json(self, out_pn):
    self.outdict["result"] = self.result
    self.outdict["files"] = self.files
    self.outdict["status"] = self.status
    self.outdict["num_files"] = len(self.files)
    
    with open(out_pn, 'w') as f:
        f.write(json.dumps(self.outdict))

  # should read json file to know the groundtruth
  def classify_all(self, json_file):

    basedir = "/tmp/output"
    with open(json_file, 'r') as fh:
      input_dict = json.load(fh)
      filelist = input_dict["files"]
      tag = input_dict["tags"]
      
      for i in xrange(len(filelist)):

        groundtruth = tag[i]["tag_b"]
        #in_pn = os.path.join(basedir, groundtruth, filelist[i])
        in_pn = os.path.join(basedir, "%scsv" % groundtruth, filelist[i]+".csv")        
        current_sample_pd = pd.read_csv(in_pn, header=None, engine='python')        

        print current_sample_pd.shape
        result_num = self.clf.predict(current_sample_pd)[0]
              
        if result_num == 1:
          result = "ben"
        elif result_num == 0:
          result = "mal"

        print "** Classifying %s:" % filelist[i]

        if result == groundtruth:
          tag_dict = {"tag_a":groundtruth, "tag_b":result}
          status = "correct"
        else:
          tag_dict = {"tag_a":groundtruth, "tag_b":result}
          status = "incorrect"

        print "  >> classified as %s. This is %s result" % (result.upper(), status.upper())

        self.files.append(filelist[i])
        self.status.append(status)
        self.result.append(tag_dict)

  def classify_one_array(self, in_array):    

    result = self.clf.predict(in_array)[0]
    if result == 1:
      return "ben", in_array
    elif result == 0:
      return "mal", in_array

  def perturb_candidate(self, json_file):
    with open(json_file, 'r') as fh:
      input_dict = json.load(fh)
      filelist = input_dict["files"]
      tag = input_dict["tags"]
      
      ben_sample_pd = self.ben_train_pd

      # let's classify this sample
      for i in xrange(len(filelist)):
        pert_candidate = []

        print "[*] Extracting information from %s" % filelist[i]
        groundtruth = tag[i]["tag_b"]
        csv_pn = os.path.join("/tmp", "output", "malcsv", filelist[i]+".csv")
        result, current_array = self.classify_one(csv_pn) 
        perturbed_array = current_array.copy().values[0]

        if result == "ben":
          print "  >>> doesn't necessary to perturb %s" % filelist[i]
          continue

        closest_benign = find_closest_benign(ben_sample_pd, perturbed_array)
        #target_perturb_idx, diff = get_highest_diff_feature(closest_benign, perturbed_array)
        #print target_perturb_idx, diff
        #comp_two_arrays(closest_benign, perturbed_array)
        sortedlist = get_highest_negdiff_feature(closest_benign, perturbed_array, 10)
        
        print " >>> should minimize this index"
        for item in sortedlist:          
          two_gram = ret_twogram_from_idx(self.two_gram, item[0])
          print "idx %d, value %d, two-gram: %s" % (item[0], item[1], two_gram)
          gram1, gram2 = two_gram.split("|")
          if gram1 not in pert_candidate:
            pert_candidate.append(gram1)
          if gram2 not in pert_candidate:
            pert_candidate.append(gram2)

        patch_candidate = self.extract_addr(filelist[i], pert_candidate)
        dump_addr(patch_candidate, PATCH_ADDR_FILE)

        # nullify call by addr
        in_pn = os.path.join("/mnt", "input", filelist[i])
        out_pn = os.path.join("/mnt", "output", filelist[i])
        patch_bin(in_pn, out_pn, PATCH_ADDR_FILE)

        # record it at the json        
        if os.path.getsize(out_pn) > 0:
          tag_dict = {"tag_a":filelist[i], "tag_b":os.path.getsize(out_pn)}
          status = "success"
        else:
          tag_dict = {"tag_a":filelist[i], "tag_b":os.path.getsize(out_pn)}
          status = "fail"

        self.files.append(filelist[i])
        self.status.append(status)
        self.result.append(tag_dict)

  def extract_addr(self, filename, pert_candidate):
    file_pn = os.path.join("/mnt", "input", filename)    
    out = {}

    # find line with "call" command
    output = _objdump_extract_calls(file_pn)    
    call_list, addr_list = extract_caller(output)
    for i in xrange(len(call_list)):
      out [addr_list[i]] = call_list[i]
    return out
                    
  # deprecated
  def gen_perturb_one(self, in_pn, out_pn):
    perturbation_count = 0

    result, current_array = self.classify_one(in_pn)    
    print "  >>> current sample classified as %s" % result
    
    if result == "ben":
      print "  >>> doesn't necessary to perturb"
      return
      
    ben_sample_pd = load_csv_files(BEN_SAMPLE_DIR, "ben", sample=True)
    
    perturbed_array = current_array.copy().values[0]
    closest_benign = find_closest_benign(ben_sample_pd, perturbed_array)

    while True:
      perturbation_count += 1
      #comp_two_arrays(closest_benign, perturbed_array)
      target_perturb_idx, diff = get_highest_diff_feature(closest_benign, perturbed_array)
      print ret_distance(closest_benign, perturbed_array)

      # increase count
      perturbed_array[target_perturb_idx] += diff
      print " >>> perturbing %dth index (current feature diff %d)" % (target_perturb_idx, diff)
      result = self.classify_one_array([perturbed_array])[0]

      if result == "ben":
        print " >>> found successful perturbation"
        break

      if perturbation_count > 300:

        print "count over"
        break
        
  def load_groundtruth(self):
  
    self.mal_train_pd = load_csv_files(self.sample_dir, "malcsv")
    self.ben_train_pd = load_csv_files(self.sample_dir, "bencsv")

    self.all_train_pd = pd.DataFrame(np.vstack([self.ben_train_pd, self.mal_train_pd]))
    self.all_train_pd = np.nan_to_num(self.all_train_pd)
    
    self.groundtruth_tr_pd = pd.Series([1]*len(self.ben_train_pd) + [0]*len(self.mal_train_pd))

  def train(self, model, argument=None):
    if model=="nn":
      assert (isinstance(argument, int), "Argument should be defined")
      n_neighbors = argument
      self.clf = neighbors.KNeighborsClassifier(n_neighbors) 
    
    elif model=="rf":
      max_depth = argument[0]
      random_state = argument[1]
      self.clf = RandomForestClassifier(max_depth=max_depth, random_state=random_state) 

    elif model=="neural":
      solver = argument[0]
      hidden_size = argument[1]
      random_state = argument[2]
      self.clf = MLPClassifier(solver=solver, alpha=1e-5, \
        hidden_layer_sizes=hidden_size, random_state=random_state)

    elif model=='gaussian':
      kernel_val = argument[0]
      RBF_val = argument[1]
      self.clf = GaussianProcessClassifier(kernel=kernel_val * RBF(length_scale=RBF_val), optimizer=None)

    elif model=="svm":
      self.clf = svm.SVC()

    self.clf.fit(self.all_train_pd, y=self.groundtruth_tr_pd)

  def ret_report(self):
    if self.crossval==True:
      print "Cross-validation result"
      predict_tr = cross_validation.cross_val_predict(self.clf, self.all_train_pd,\
                                                    y=self.groundtruth_tr_pd, cv=3, n_jobs=8)
      cm = confusion_matrix(self.groundtruth_tr_pd, predict_tr)
      a,b,c,d = cm.ravel()  
      report = metrics.classification_report(self.groundtruth_tr_pd, predict_tr)

    else:      
      predict_tr = self.clf.predict(self.all_train_pd)      
      cm = confusion_matrix(self.groundtruth_tr_pd, predict_tr)
      a,b,c,d = cm.ravel()
      report = metrics.classification_report(self.groundtruth_tr_pd, predict_tr)

    try:
      print_matrix(cm)
    except:
      pass
    print report

  def load_model(self, in_pn):
    with open(in_pn, 'rb') as f:
      pickle_obj = pickle.load(f)
      self.clf = pickle_obj["model"]
      self.two_gram = pickle_obj["two-gram"]
      self.ben_train_pd = pickle_obj["benign"]

  def save_model(self, out_pn):    
    print "[*] Saving model now!"
    #assume that feature_mlsploit.py collectly generate two_gram_mini.pkl (/mnt/output/)
    with open ("/mnt/output/two_gram_mini.pkl") as f_two:
      two_grams = pickle.load(f_two)

    model_name = out_pn

    out = {}
    out["model"] = self.clf
    out["two-gram"] = two_grams
    out["benign"] = self.ben_train_pd

    with open(model_name, 'wb') as f:
      pickle.dump(out, f)

    # take care of output.json file
    self.result.append ({"tag_a":"%s classifier" % self.model})
    self.files.append(os.path.basename(out_pn))
    if os.path.getsize(model_name) > 0:
      self.status.append("success")
    else:
      self.status.append("fail")

def main():

  ## start program 
  mal_dir = "/mnt/input/mal"
  ben_dir = "/mnt/input/ben"
  in_dir = os.path.join("/mnt", "input")
  out_dir = os.path.join("/mnt", "output")
  input_json = "/mnt/input/input.json"
  output_json = "/mnt/output/output.json"

  action = str(read_json(input_json, "action"))
  name = str(read_json(input_json, "name"))

  if name == "train":    
    # e.g., python classifier_mlsploit.py save -o nn.pkl -i processed/csv/indiv -a nn    
    
    model_file = str(read_json(input_json, "model"))
    algorithm = str(read_json(input_json, "option")["algorithm"])
    
    print "[*] processing training"
    print " >>> user specified %s algorithm" % algorithm
    print " >>> module will store model at: %s" % model_file    

    in_dir = os.path.join("/tmp", "output")

    cf = Classifier(in_dir, crossval=False, action=action, name=name, model=algorithm)
    cf.train(model=algorithm, argument = argu_dict[algorithm])

    # assume that feature_mlsploit.py collectly generate two_gram_mini.pkl (/mnt/output/)
    cf.save_model(os.path.join(out_dir, model_file))
    cf.dump_json(output_json)
    cf.ret_report()

  elif name == "classification":

    #model = args.model    
    model_file = str(read_json(input_json, "model"))
    distribute_files (input_json, mal_dir, ben_dir)

    print "[*] processing evaluation"
    print " >>> user specified model at: %s" % model_file

    # we want to work with temporal csv
    in_dir = os.path.join("/tmp", "output")

    cf = Classifier(in_dir, crossval=False, action=action, name=name)
    cf.load_model(os.path.join("/mnt", "input", model_file))
    cf.classify_all(input_json)
    cf.dump_json(output_json)

  elif name == "rmapi":
    """
    - assuming multiple files
    - assuming auto removal
    - store which feature be removed into log files    
    - include all files (tag will specify which file to be perturbed)
    - automatically construct benign set from samples
    - bypassing target should be malware
    """

    # input should contain model file 
    model_file = str(read_json(input_json, "model"))

    # we want to work with temporal csv
    in_dir = os.path.join("/tmp", "output")

    cf = Classifier(in_dir, crossval=False, action=action, name=name)
    cf.load_model(os.path.join("/mnt", "input", model_file))
    cf.perturb_candidate(input_json)
    cf.dump_json(output_json)
    
  elif name == "injectapi":
    # input should contain model file 
    model_file = str(read_json(input_json, "model"))

    # we want to work with temporal csv
    in_dir = os.path.join("/tmp", "output")

    cf = Classifier(in_dir, crossval=False, action=action, name=name)
    cf.load_model(os.path.join("/mnt", "input", model_file))
    cf.perturb_candidate(input_json)
    cf.dump_json(output_json)
    
  
if __name__ == "__main__":
  main()

# check pkl file
"""
import pickle
with open("nn.pkl", 'rb') as f:
  pickle_obj = pickle.load(f)
  for key in pickle_obj.keys():
    print  key

"""