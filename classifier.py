#!/usr/bin/env python2
import sys
import glob
import pickle
import numpy as np
import pandas as pd

# required model
from sklearn import svm
from sklearn import neighbors, metrics, preprocessing 
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF

# required aux
from sklearn import cross_validation, grid_search
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.externals import joblib
#from mamastat_one import *
from conf import *

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

# deprecated
"""
def get_highest_diff_feature(minimum, target):
  
  #1. compare two lists
  #2. return idx of that feature (biggest difference)
  #3. we are considering some feature we can inject
  #   (instead of removal)
  #  - (minimum - target) should be positive
  
  sub_arr =  np.subtract(minimum, target).tolist()
  largest_num_idx = sub_arr.index(max(sub_arr))
  difference = minimum[largest_num_idx] - target[largest_num_idx]  
  #difference = sub_arr[largest_num_idx]
  return largest_num_idx, difference

"""

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
  files = glob.glob(dirname+"/%s*" % kind)
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
  def __init__(self, sample_dir, crossval=False):
    self.sample_dir = sample_dir
    self.ben_train_pd = None
    self.mal_train_pd = None
    self.all_train_pd = None
    self.groundtruth_tr_pd_pd = None
    self.clf = None
    self.crossval = crossval

    self.load_groundtruth()

  def classify_one(self, in_pn):    

    #current_sample_pd = pd.DataFrame.from_csv(in_pn, engine='python')
    current_sample_pd = pd.read_csv(in_pn, header=None, engine='python')
        
    result = self.clf.predict(current_sample_pd)[0]
    if result == 1:
      return "ben", current_sample_pd
    elif result == 0:
      return "mal", current_sample_pd

  def classify_one_array(self, in_array):    

    result = self.clf.predict(in_array)[0]
    if result == 1:
      return "ben", in_array
    elif result == 0:
      return "mal", in_array

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
  
    self.mal_train_pd = load_csv_files(self.sample_dir, "mal")
    self.ben_train_pd = load_csv_files(self.sample_dir, "ben")

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
      self.clf = pickle.load(f)

  def save_model(self, out_pn):    
    model_name = out_pn
    with open(model_name, 'wb') as f:
      pickle.dump(self.clf, f)  


def main():
  # for test
  sample_dir = os.path.join("processed", "indiv")
  one_sample = os.path.join("processed", "indiv", "mal10.csv")
  out_perturb = os.path.join("/tmp", "perturb.csv")
  cf = Classifier(sample_dir, crossval=False)

  cf.train(model="nn", argument=1)  # number of neighbor
  #cf.train(model="rf", argument=[7,2]) # maxdepth, random_state
  #cf.train(model="neural", argument=["lbfgs", (5,2), 1]) # solver(lbfgs, sgd, adam), hidden_layer_size, random_state
  #cf.train(model="gaussian", argument=[1.0, 1.0]) # kernel, RBF
  #cf.train(model="svm", argument=None)
  
  #cf.save_model("/tmp/nn_mini.pkl")
  #cf.load_model("/tmp/nn_mini.pkl")

  cf.classify_one(one_sample)
  cf.gen_perturb_one(one_sample, out_perturb)
  
  #cf.ret_report()

if __name__ == "__main__":
  main()  