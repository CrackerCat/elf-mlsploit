import ast
import argparse
import requests
import os
import time
import commands
import pprint

from conf import *

mal_files = ["mal1", "mal2", "mal3"]
ben_files = ["ben1", "ben2", "ben3"]

test_file = ["mal4"]

upload_filelist = "/tmp/.upfiles"
classified_filelist = "/tmp/.classified"

def extract_id(_dict):
    return _dict["id"]

def extract_id2(line):
    id = line.split("id\":")[1].split(",")[0].strip()
    return id

def extract_finished(line):
    finished = line.split("status\":")[1].split(",")[0].strip()
    return finished

def get_class_result(line):
    result = line.split("classified as")[1].split("This")[0].strip()
    return result

class Wrap(object):
    def __init__(self):
        self.list = self.ret_module_list()
        self.sample_list = self.ret_sample_list()
        
    def ret_module_list(self):        
        response = requests.get('%s/api/module/list/' % SERVER)        
        output = response.text
        return ast.literal_eval(output)

    def ret_sample_list(self):
        response = requests.get('%s/api/data/list/' % SERVER)
        output = response.text
        return ast.literal_eval(output)

    def upload_sample(self, pn):
        id = 0
        cmd = "curl -s -X POST %s/api/data/upload/ -H 'Content-Type: multipart/form-data' -F 'data=@%s'" % (SERVER, pn)
        out = commands.getoutput(cmd)
        #print out
        id_dict = ast.literal_eval(out)

        id = extract_id(id_dict)        
        if id != 0:
            return id

    def rm_sample(self, id):
        #curl -X POST http://3.17.28.222:8000/api/data/remove/<sample_id>
        id_list = id.split(",")
        for fileid in id_list:
            response = requests.post('%s/api/data/remove/%s/' % (SERVER, fileid))
            if "[]" in response.text:
                print "success remove %s" % fileid

    def tag(self, id, key, val):
        #curl -X POST http://3.17.28.222:8000/api/data/tag/<sample_id>/<key>/<value>/
        # /api/data/tag/<key>:<str or int or bool or float>:<value>/None/
        response = requests.post('%s/api/data/tag/%s/%s:str:%s/None/' % (SERVER, id, key, val))
        #print response.text

    def check_job(self, id):
        #curl -X GET http://3.17.28.222:8000/api/job/info/<job_id>
        response = requests.get('%s/api/job/info/%s/' % (SERVER, id))
        output = response.text
        #return ast.literal_eval(output) 
        return output

    def download_sample(self, id, out_pn):
        #curl -X GET http://3.17.28.222:8000/api/model/download/<model_id>
        print '%s/api/data/download/%s/' % (SERVER, id)
        response = requests.get('%s/api/data/download/%s/' % (SERVER, id))
        with open(out_pn, 'wb') as f:
            f.write(response.content)

def main():    
    pp = pprint.PrettyPrinter(indent=4)

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='arguments')

    mod_list = subparsers.add_parser('list', help='list available modules', add_help=False)
    mod_list.set_defaults(action='list')

    sam_list = subparsers.add_parser('samlist', help='list available samples', add_help=False)
    sam_list.set_defaults(action='samlist')

    up_sam = subparsers.add_parser('upsam', help='upload sample', add_help=False)
    up_sam.set_defaults(action='upsam')
    up_sam.add_argument("-f", "--file", dest="filename", type=str,
         default=None, help="upload sample path",required=True)

    classify_file = subparsers.add_parser('classify', help='classify sample', add_help=False)
    classify_file.set_defaults(action='classify')
    classify_file.add_argument("-f", "--file", dest="filename", type=str,
         default=None, help="sample path to be classified",required=True)
    classify_file.add_argument("-g", "--groundtruth", dest="ground", type=str,
         default=None, help="sample file's groundtruth",required=True)

    rm_sam = subparsers.add_parser('rmsam', help='remove sample', add_help=False)
    rm_sam.set_defaults(action='rmsam')
    rm_sam.add_argument("-i", "--id", dest="fileid", type=str,
         default=None, help="remove sample id",required=True)

    tag_sam = subparsers.add_parser('tag', help='tag sample', add_help=False)
    tag_sam.set_defaults(action='tag')
    tag_sam.add_argument("-i", "--id", dest="fileid", type=str,
         default=None, help="tag sample id",required=True)
    tag_sam.add_argument("-k", "--key", dest="key", type=str,
         default=None, help="tag sample key",required=True)
    tag_sam.add_argument("-v", "--val", dest="val", type=str,
         default=None, help="tag sample value",required=True)

    eval1 = subparsers.add_parser('eval', help='upload samples (ben and mal)', add_help=False)
    eval1.set_defaults(action='eval')
    eval1.add_argument("-p", "--phase", dest="phase", type=str,
         default=None, help="evaluation phase",required=True)

    args = parser.parse_args()
    wrap = Wrap()

    if args.action == "list":
        #print wrap.list
        pp.pprint (wrap.list)

    if args.action == "samlist":
        #print wrap.sample_list
        pp.pprint (wrap.sample_list)

    if args.action == "upsam":
        filename = args.filename
        pp.pprint(wrap.upload_sample(filename))

    if args.action == "rmsam":
        fileid = args.fileid
        wrap.rm_sample(fileid)

    if args.action == "tag":
        fileid = args.fileid
        key = args.key
        val = args.val
        pp.pprint(wrap.tag(fileid, key, val))

    if args.action == "classify":
        # upload
        filename = args.filename
        id_list = []        
        print "Uploading %s and tagging..." % filename        
        id = wrap.upload_sample(filename)
        key = "tag_a"
        val = os.path.basename(filename)
        wrap.tag(id, key, val)
        key = "tag_b"
        val = "mal"
        wrap.tag(id, key, val)
        id_list.append(id)

        # classify
        ids = str(id_list)
        with open(classified_filelist, 'w') as f:
            f.write(ids)

        cmd = "curl -s -X POST %s/api/job/submit/ -H 'Content-Type: application/json; charset=UTF-8'  -d '{\"module\": \"elf\", \"function\": \"cla\", \"sample_ids\": %s, \"option\": {}, \"model\": 3}'" \
        % (SERVER, ids)
        id_dict = commands.getoutput(cmd)            
        #id_dict = ast.literal_eval(out)

        id = extract_id2(str(id_dict))

        while True:
            time.sleep(5)
            print "Checking status job %s." % id
            current_job = wrap.check_job(id)
            print " >>>", extract_finished(current_job)
            if "FINI" not in extract_finished(current_job):
                continue
            else:
                #print current_job
                print 
                print "Classification result:", get_class_result(current_job)
                break 

    if args.action == "eval":

        if args.phase == "init_upload":
            id_list = []
            for malfile in mal_files:            
                print "Uploading %s and tagging..." % malfile
                pn = os.path.join("/tmp", malfile)
                id = wrap.upload_sample(pn)
                key = "tag_a"
                val = malfile
                wrap.tag(id, key, val)
                key = "tag_b"
                val = "mal"
                wrap.tag(id, key, val)
                id_list.append(id)

            for benfile in ben_files:
                print "Uploading %s and tagging..." % benfile
                pn = os.path.join("/tmp", benfile)
                id = wrap.upload_sample(pn)            
                key = "tag_a"
                val = benfile
                wrap.tag(id, key, val)
                key = "tag_b"
                val = "ben"
                wrap.tag(id, key, val)
                id_list.append(id)

            print "Upload complete, IDs are:"
            print id_list
            with open(upload_filelist,'w') as f:
                f.write(str(id_list))

        if args.phase == "init_train":
            ids = open(upload_filelist, 'r').read()
            cmd = "curl -s -X POST %s/api/job/submit/ -H 'Content-Type: application/json; charset=UTF-8'  -d '{\"module\": \"elf\", \"function\": \"tra\", \"sample_ids\": %s, \"option\": {\"algorithm\":\"nn\"}, \"model\": 3}'" \
            % (SERVER, ids)
            #os.system(cmd)
            id_dict = commands.getoutput(cmd)

            id = extract_id2(str(id_dict))

            while True:
                time.sleep(5)
                print "Checking status job %s." % id
                current_job = wrap.check_job(id)
                print " >>>", extract_finished(current_job)
                if "FINI" not in extract_finished(current_job):
                    continue
                elif "FAILED" in extract_finished(current_job):
                    print "TRAINING Failed!"
                    break
                else:
                    #print current_job
                    print 
                    print "Training DONE"
                    break 

        if args.phase == "init_class":
            id_list = []

            for malfile in test_file:                
                pn = os.path.join("/tmp", malfile)
                id = wrap.upload_sample(pn)
                key = "tag_a"
                val = malfile
                wrap.tag(id, key, val)
                key = "tag_b"
                val = "mal"
                wrap.tag(id, key, val)
                id_list.append(id)
                print "Uploading %s and tagging as ID: %s" % (malfile, id)

            ids = str(id_list)
            with open(classified_filelist, 'w') as f:
                f.write(ids)

            cmd = "curl -s -X POST %s/api/job/submit/ -H 'Content-Type: application/json; charset=UTF-8'  -d '{\"module\": \"elf\", \"function\": \"cla\", \"sample_ids\": %s, \"option\": {}, \"model\": 3}'" \
            % (SERVER, ids)
            id_dict = commands.getoutput(cmd)            
            #id_dict = ast.literal_eval(out)

            id = extract_id2(str(id_dict))

            while True:
                time.sleep(5)
                print "Checking status job %s." % id
                current_job = wrap.check_job(id)
                print " >>>", extract_finished(current_job)
                if "FINI" not in extract_finished(current_job):
                    continue
                else:
                    #print current_job
                    print 
                    print "Classification result:", get_class_result(current_job)
                    break 

        if args.phase == "perturb":
            # perturb            
            ids_string = open(classified_filelist, 'r').read()
            ids = ast.literal_eval(ids_string)
            cmd = "curl -s -X POST %s/api/job/submit/ -H 'Content-Type: application/json; charset=UTF-8'  -d '{\"module\": \"elf\", \"function\": \"rmapi\", \"sample_ids\": %s, \"option\": {}, \"model\": 3}'" \
            % (SERVER, ids_string)
            os.system(cmd)
            # should return the ID

            # download            
            for i in xrange(len(ids)):
                fname = test_file[i]
                id = ids[i]
                out_pn = os.path.join("/tmp", fname+"_pert")
                wrap.download_sample(id, out_pn)

        if args.phase == "retrain":
            id_list = []
            for malfile in mal_files:            
                print "Uploading %s and tagging..." % malfile
                pn = os.path.join("/tmp", malfile)
                id = wrap.upload_sample(pn)
                key = "tag_a"
                val = malfile
                wrap.tag(id, key, val)
                key = "tag_b"
                val = "mal"
                wrap.tag(id, key, val)
                id_list.append(id)

            for benfile in ben_files:
                print "Uploading %s and tagging..." % benfile
                pn = os.path.join("/tmp", benfile)
                id = wrap.upload_sample(pn)            
                key = "tag_a"
                val = benfile
                wrap.tag(id, key, val)
                key = "tag_b"
                val = "ben"
                wrap.tag(id, key, val)
                id_list.append(id)

            print "Uploading perturbed sample and tagging..."
            for i in xrange(5):
                pn = os.path.join("/tmp", test_file[0]+"_pert")
                os.system("cp %s %s" % (pn, pn+str(i)))
                id = wrap.upload_sample(pn+str(i))
                key = "tag_a"
                val = test_file[0]+"_pert"+str(i)
                wrap.tag(id, key, val)
                key = "tag_b"
                val = "mal"
                wrap.tag(id, key, val)
                id_list.append(id)     

            print "Upload complete, IDs are:"
            print id_list
            with open(upload_filelist,'w') as f:
                f.write(str(id_list))           

            print "Now start training..."
            ids = open(upload_filelist, 'r').read()
            cmd = "curl -s -X POST %s/api/job/submit/ -H 'Content-Type: application/json; charset=UTF-8'  -d '{\"module\": \"elf\", \"function\": \"tra\", \"sample_ids\": %s, \"option\": {\"algorithm\":\"nn\"}, \"model\": 3}'" \
            % (SERVER, ids)
            os.system(cmd)

        if args.phase == "re_class":
            id_list = []

            for malfile in test_file:                
                pn = os.path.join("/tmp", malfile+"_pert")
                id = wrap.upload_sample(pn)
                key = "tag_a"
                val = malfile
                wrap.tag(id, key, val)
                key = "tag_b"
                val = "mal"
                wrap.tag(id, key, val)
                id_list.append(id)
                print "Uploading %s and tagging as ID: %s" % (malfile+"_pert", id)

            ids = str(id_list)
            with open(classified_filelist, 'w') as f:
                f.write(ids)

            cmd = "curl -s -X POST %s/api/job/submit/ -H 'Content-Type: application/json; charset=UTF-8'  -d '{\"module\": \"elf\", \"function\": \"cla\", \"sample_ids\": %s, \"option\": {}, \"model\": 3}'" \
            % (SERVER, ids)
            id_dict = commands.getoutput(cmd)            
            #id_dict = ast.literal_eval(out)

            id = extract_id2(str(id_dict))

            while True:
                time.sleep(5)
                print "Checking status job %s." % id
                current_job = wrap.check_job(id)
                print " >>>", extract_finished(current_job)
                if "FINI" not in extract_finished(current_job):
                    continue
                else:
                    #print current_job
                    print 
                    print "Classification result:", get_class_result(current_job)
                    break 
        
if __name__ == "__main__":
    main()
