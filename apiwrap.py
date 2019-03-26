import ast
import argparse
import requests

class Wrap(object):
    def __init__(self):
        self.list = self.ret_list()
        
    def ret_list(self):
        response = requests.get('http://3.16.213.172:8000/api/module/list/')        
        output = response.text
        return ast.literal_eval(output)[0]

def main():    
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='arguments')

    func_list = subparsers.add_parser('list', help='list available modules', add_help=False)
    func_list.set_defaults(action='list')

    args = parser.parse_args()

    wrap = Wrap()

    if args.action == "list":
        print wrap.list

if __name__ == "__main__":
    main()  