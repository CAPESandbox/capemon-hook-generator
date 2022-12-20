#!/usr/bin/python3
# RazviOverflow

import os
import pefile
from pprint import pprint
import sys
import requests
import re
#from googlesearch import search
from bs4 import BeautifulSoup
import pathlib
import random

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
                dll_exports[exp.name.decode('utf-8')] = pathlib.PurePath(dll).stem # To get only .dll file, not full path
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

def get_microsoft_learn_entry(api_name):
    # We query Google for site:learn.microsoft.com api_name and get 1st result
    #query = "{} site:learn.microsoft.com".format(api_name)
    #query = "https://learn.microsoft.com/en-us/search/?terms={}".format(api_name)
    query = "https://www.google.com/search?q={}+site%3Alearn.microsoft.com%2Fen-us%2F".format(api_name)
    
    headers = {'User-Agent': random.choice(
            [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
                'Mozilla/5.0 (Windows NT 10.0; Win 64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36',
            ]
        )
    }

    # https://github.com/Nv7-GitHub/googlesearch
    print("Query: {}".format(query))
    # Internally it uses a random user agent https://github.com/Nv7-GitHub/googlesearch/blob/master/googlesearch/__init__.py#L7
    results = requests.get(query, timeout = None, headers=headers)
    print(results.text)
    for result in results:
        print("[*] Query results: {}".format(result))
    return results[0]


def obtain_SAL_prototype(api_name):
    microsoft_learn_URL = get_microsoft_learn_entry(api_name)
    sys.exit()
    #microsoft_learn_URL = "https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationa"
    #microsoft_learn_URL = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-acquiresrwlockexclusive"
    r = requests.get(microsoft_learn_URL)
    result = BeautifulSoup(r.text, "html.parser")
    result = result.find("code", class_="lang-cpp")
    result = result.text # Result now contains the SAL notation as stated by learn.microsoft
    return result

def append_hook_h(api_name, return_type, calling_convention, parameters):
    with open("extended_hooks.h", "a") as file:
        file.write("HOOKDEF({} ,{} ,{},{});".format(return_type, calling_convention, api_name, parameters))

def append_hook_c(api_name, dll):
    with open("extended_hooks.c", "a") as file:
        file.write("HOOK({}, {}),".format(dll, api_name))

def append_hook_misc_c(api_name, return_type, calling_convention, parameters):
    with open("extended_hook_misc.c", "a") as file:
        file.write("HOOKDEF({} ,{} ,{},{}){{\n".format(return_type, calling_convention, api_name, parameters))
        file.write("\tDebuggerOutput(\"[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked {}\\n\");\n".format(api_name))
        if return_type == 'void':
            file.write("\tOld_{}(".format(api_name))
            # Transform the SAL parameters into a list comprising only their names
            for parameter in parameters.strip().split("\n"):
                file.write(parameter.split()[-1])
            file.write(");\n")
            file.write("\tLOQ_bool(\"misc\", \"\");\n")
        else:
            file.write("\t{} ret = Old_{}(".format(return_type, api_name));
            for parameter in parameters.strip().split("\n"):
                file.write(parameter.split()[-1])
            file.write(");\n")
            file.write("\tLOQ_bool(\"misc\", \"\");\n")
            file.write("\treturn ret;\n")
        file.write("\n}")

# Function used to transform parameters according to true SAL notation.
# https://learn.microsoft.com/en-us/cpp/code-quality/understanding-sal?view=msvc-170
# Example: [in, out] -> _Inout_
def transform_SAL_parameters(parameters):
    # All SAL types https://learn.microsoft.com/en-us/cpp/code-quality/annotating-function-parameters-and-return-values?view=msvc-170
    parameters = parameters.replace("[in]", "_In_")
    parameters = parameters.replace("[in, out]", "_Inout_")
    parameters = parameters.replace("[out]", "_Out_")
    parameters = parameters.replace("[in, optional]", "_In_opt_")
    parameters = parameters.replace("[out, optional]", "_Out_opt_")
    return parameters

def generate_hooks(api_name, dll):
    
    SAL_notation = obtain_SAL_prototype(api_name)

    # Parse the SAL_notation text and transform it to hooks.h syntax
    return_type = SAL_notation[:SAL_notation.index(api_name)].strip() # Everything before the api_name itself is the ret type
    calling_convention = "WINAPI" # ****ATTENTION!**** WINAPI is assumid, but it might be incorrect (notice winsock2.h, for example)
    parameters = SAL_notation[SAL_notation.index('(')+1:SAL_notation.index(')')] #+1 to skip '('
    parameters = transform_SAL_parameters(parameters)
    # Generate entry for hooks.h
    append_hook_h(api_name, return_type, calling_convention, parameters)
    
    # Generate entry for hooks.c
    append_hook_c(api_name, dll)
    
    # Generate entry for hooks_misc.c
    append_hook_misc_c(api_name, return_type, calling_convention, parameters)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
    else :
        for dll in sys.argv[1:]:
            # Obtain APIs from EAT of given dll(s)
            obtain_exports(dll) 

        # If hooks.c file does not exist, download it    
        obtain_hooks_file() 

        # Parse the file and create a dictionary of APIs already hooked
        #get_capemon_hooks() 
        #generate_hooks("GetVolumeInformationA", dll_exports["GetVolumeInformationA"])
        
        for hook in dll_exports:
            if hook not in capemon_hooks:
                generate_hooks(hook, dll_exports[hook])
        


    