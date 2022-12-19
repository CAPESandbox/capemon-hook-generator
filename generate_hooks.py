#!/usr/bin/python3
# RazviOverflow


import os
import pefile
from pprint import pprint
import sys
import requests
import re

# GLOBALS #
# Using dictionaries because of lookup performance https://towardsdatascience.com/faster-lookups-in-python-1d7503e9cd38
dll_exports = {}
capemon_hooks = {}

def print_usage():
    print("[+] Usage:\n\tpython3 generate_hooks.py dll_1.dll dll_2.dll ... or:")
    print("\t./generate_hooks.py dll_1.dll dll_2.dll ...")

def obtain_exports(dll):
    try:
        pe = pefile.PE(dll)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                dll_exports[exp.name.decode('utf-8')] = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
            except:
                continue
    except Exception as e:
        print("[!] Error: {}".format(e))

def obtain_hooks_file():
    if not os.path.exists("hooks.c"):
        print("[*] hooks.c file not detected. Downloading from original capemon repo (https://github.com/kevoreilly/capemon\n")
        r = requests.get("https://raw.githubusercontent.com/kevoreilly/capemon/capemon/hooks.c")
        #print(r.text)
        with open("hooks.c", "w") as hooks_file:
            hooks_file.write(r.text)
           
def get_capemon_hooks():
    with open("hooks.c", "r") as file:
        line = file.readline()
        #global capemon_hooks
        while line:
            # Line starts with HOOK( or HOOK___(
            line = line.strip()
            if line.startswith("HOOK"):
                startIndex = line.index(',')
                endIndex = line.index(')')
                line = line[startIndex: endIndex] # Two forms: either [, LdrLoadDll, 4] or [, NtCreateUserProcess]
                line = line[2:] 
                if ',' in line: 
                    line = line[:line.index(',')]
                capemon_hooks[line] = "" # Since capemon_hooks is a dictionary, keys are automatically unique
            line = file.readline()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
    else :
        for dll in sys.argv[1:]:
            obtain_exports(dll)
        obtain_hooks_file() # If hooks.c file does not exist, download it
        get_capemon_hooks()
        pprint(capemon_hooks, sort_dicts=False)


    