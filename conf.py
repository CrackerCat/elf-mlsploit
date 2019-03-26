#MAL_DIR = "samples/mal_strip_mini"
#BEN_DIR = "samples/benign_mini"

import os

# define keyword
INDIRECT = "indirect"
ADDR     = "address"
NONE     = "none"
RARELY   = "rarely"

# define number of features
NUM_DICT = 3000

# define file paths
DICT_NAME = os.path.join("/mnt", "output", "two_gram_mini.pkl") 
BEN_SAMPLE_DIR = os.path.join("processed", "csv", "indiv")
PATCH_ADDR_FILE = os.path.join("/tmp", "addr_candidate")

# temporal variable to save time
CLASSIFY_LIMIT = 10
MAX_PATCH = 20

# arugment for the classifier
argu_dict = {}
argu_dict["nn"] = 1
argu_dict["rf"] = [7,2]
argu_dict["neural"] = ["lbfgs", (5,2), 1]
argu_dict["gaussian"] = [1.0, 1.0]
argu_dict["svm"] = None

SERVER = "https://mlsploit.org/"