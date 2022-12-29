#!/usr/bin/python3
# RazviOverflow

import os
import json
import pefile
from pprint import pprint
import sys
import requests
import re
#from googlesearch import search
from bs4 import BeautifulSoup
import pathlib
import random
from googleapiclient.discovery import build

# GLOBALS #
# Using dictionaries because of lookup performance https://towardsdatascience.com/faster-lookups-in-python-1d7503e9cd38
dll_exports = {}
capemon_hooks = {}

# GOOGLE API https://programmablesearchengine.google.com/
# https://developers.google.com/custom-search/v1/introduction -> Get a Key
GOOGLE_API_KEY = "" # Change with your own Custom Search API KEY in config.ini
# https://programmablesearchengine.google.com/controlpanel/all
GOOGLE_CSE_ID = "" # Change with your own CSE ID in config.ini
GOOGLE_SEARCH = False # Modified to True in case API keys are specified
JSON_DATA = "" # Assigned once winapi_categories.json is loaded


def print_usage():
    print("[+] Usage:\n\tpython3 generate_hooks.py dll_1.dll dll_2.dll ... or:")
    print("\t./generate_hooks.py dll_1.dll dll_2.dll ...")

def read_api_keys():
    try:
        with open("config.ini") as file:
            data = json.load(file)
            global GOOGLE_API_KEY, GOOGLE_CSE_ID
            GOOGLE_API_KEY = data['GOOGLE_API_KEY']
            GOOGLE_CSE_ID = data['GOOGLE_CSE_ID']
            if GOOGLE_API_KEY == "CHANGE_ME!" or GOOGLE_CSE_ID == "CHANGE_ME!":
                print("[!] Google API keys unspecified")
                return False
        return True
    except Exception as e:
        print(f"[!!!] Error while reading config.ini -> {e}")
        return False

def obtain_winapi_file():
    if not os.path.exists("winapi_categories.json"):
        print("[*] winapi_categories.json file not detected. Downloading from repo (https://github.com/RazviOverflow/winapi_categories_json)\n")
        r = requests.get("https://raw.githubusercontent.com/RazviOverflow/winapi_categories_json/main/winapi_categories.json")
        with open("winapi_categories.json", "w") as hooks_file:
            hooks_file.write(r.text)
    else:
        print("[*] winapi_categories.json file detected.")

def obtain_exports(dll):
    try:
        pe = pefile.PE(dll)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                dll_exports[exp.name.decode('utf-8')] = pathlib.PurePath(dll).stem # To get only .dll file, not full path
            except:
                continue
    except Exception as e:
        print("[!!!] Error: {}".format(e))

def obtain_hooks_file():
    if not os.path.exists("hooks.c"):
        print("[*] hooks.c file not detected. Downloading from original capemon repo (https://github.com/kevoreilly/capemon)")
        r = requests.get("https://raw.githubusercontent.com/kevoreilly/capemon/capemon/hooks.c")
        with open("hooks.c", "w") as hooks_file:
            hooks_file.write(r.text)
    else:
        print("[*] hooks.c file not detected")

def search_api_in_json_file(api_name):
    print(f"[*] Looking for {api_name} in winapi_categories_json")
    return_value = False
    if api_name in JSON_DATA:
        return_value = {}
        return_value['return_type'] = JSON_DATA[api_name]['return_type']
        return_value['parameters'] = JSON_DATA[api_name]['arguments']
        print(f"[*] {api_name} found in winapi_categories_json")
    else:
        print(f"[*] {api_name} not found in winapi_categories_json")
    return return_value
           
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

def google_search(search_term, **kwargs):
    service = build("customsearch", "v1", developerKey=GOOGLE_API_KEY)
    res = service.cse().list(q=search_term, cx=GOOGLE_CSE_ID, **kwargs).execute()
    return res

def get_microsoft_learn_entry(api_name):
    results = google_search(api_name)
    if not "items" in results: # In case there are no results
        return False
    return results["items"][0]["link"] # Get only "link" from the 1st result


def obtain_SAL_prototype(api_name):
    result = False

    data = search_api_in_json_file(api_name)
    if not data:
        print(f"[!!!] Couldn't find entry for {api_name} in winapi_categories_json!")
        if GOOGLE_SEARCH:
            print(f"[*] Googling for {api_name}!")
            microsoft_learn_URL = get_microsoft_learn_entry(api_name)
            if not microsoft_learn_URL:
                print(f"[!!!] Couldn't find entry for {api_name} in Google!")
            else:
                print(f"[*] Found results in Google for {api_name}!")
                r = requests.get(microsoft_learn_URL)
                result = BeautifulSoup(r.text, "html.parser")
                result = result.find("code", class_="lang-cpp")
                if result is None:
                    result = BeautifulSoup(r.text, "html.parser")
                    result = result.find("code", class_="lang-C") # Some entries are marked with lang-C rather than lang-cpp
                if result is None:
                    result = BeautifulSoup(r.text, "html.parser")
                    result = result.find("code", class_="lang-C++") # Some entries are marked with lang-C++ rather than lang-cpp or lang-C
                if result is None:
                    print(f"[!!!] ERROR. Couldn't find exact entry for {api_name}. Consider manually looking for it. Skipping to next API call!")
                result = result.text # Result now contains the SAL notation as stated by learn.microsoft
    else:
        result = data    
    return result

def append_hook_h(api_name, return_type, calling_convention, parameters):
    with open("extended_hooks.h", "a") as file:
        file.write(f"HOOKDEF({return_type}, {calling_convention}, {api_name},\n{parameters}\n);\n\n")

def append_hook_c(api_name, dll):
    with open("extended_hooks.c", "a") as file:
        file.write(f"HOOK({dll}, {api_name}),\n")

def append_hook_misc_c(api_name, return_type, calling_convention, parameters):
    with open("extended_hook_misc.c", "a") as file:
        file.write(f"HOOKDEF({return_type} ,{calling_convention} ,{api_name},\n{parameters}\n){{\n")
        file.write(f"\tDebuggerOutput(\"[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked {api_name}\\n\");\n")
        if return_type == 'void':
            file.write("\tOld_{}(".format(api_name))
            # Transform the SAL parameters into a list comprising only their names
            if len(parameters) > 2:
                for parameter in parameters.strip().split("\n"):
                    file.write(parameter.split()[-1])
            file.write(");\n")
            file.write("\tLOQ_bool(\"misc\", \"\");\n")
        else:
            file.write("\t{} ret = Old_{}(".format(return_type, api_name));
            if len(parameters) > 2:
                for parameter in parameters.strip().split("\n"):
                    file.write(parameter.split()[-1])
            file.write(");\n")
            file.write("\tLOQ_bool(\"misc\", \"\");\n")
            file.write("\treturn ret;\n")
        file.write("}\n\n")

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
    print(f"[+++] Generation of hook for {api_name} started")
    SAL_notation = obtain_SAL_prototype(api_name)

    # If API is found in winapi_categories.json, its type is <class 'dict'>
    # if it is found in Google + learn.microsoft.com, its type is <class 'str'>
    # if it isn't found, the variable is just false
    if SAL_notation == False:
        print(f"[!!!] Couldn't generate hook for {api_name}, skipping API call!")
        return
    elif type(SAL_notation) is dict:
        return_type = SAL_notation['return_type']
        calling_convention = "WINAPI"
        parameters = ""
        for parameter in SAL_notation['parameters']:
            local_parameter = f"\t{parameter['in_out']} {parameter['type']} {parameter['name']},\n"
            parameters += local_parameter
        parameters = parameters[:-2] # Delete last trailing comma and newline

    elif type(SAL_notation) is str:
        try:
            # Parse the SAL_notation text and transform it to hooks.h syntax
            return_type = SAL_notation[:SAL_notation.index(api_name)].strip() # Everything before the api_name itself is the ret type
            calling_convention = "WINAPI" # ****ATTENTION!**** WINAPI is assumid, but it might be incorrect (notice winsock2.h, for example)
            parameters = SAL_notation[SAL_notation.index('(')+1:SAL_notation.index(')')].strip() #+1 to skip '('
            parameters = transform_SAL_parameters(parameters)
        except Exception as e:
            print(f"[!!!] Error occurred while Googling for {api_name}. Skipping to next API call!")
            print(f"[!!!] ERROR: {e}")
            return
    else:
        print("[!!!] ERROR. Variable type not recognized. Unexpected behavior taking place. Aborting!")
        sys.exit()
    
    # Generate entry for hooks.h
    append_hook_h(api_name, return_type, calling_convention, parameters)
    
    # Generate entry for hooks.c
    append_hook_c(api_name, dll)
    
    # Generate entry for hooks_misc.c
    append_hook_misc_c(api_name, return_type, calling_convention, parameters)

    print("[+++] Generation of hook finished")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
    else :
        if read_api_keys():
            GOOGLE_SEARCH = True
        else:
            print("[!!!] Couldn't read Google API keys, skipping scrapping")

        # Obtain winapi_categories.json if it isn't already present
        obtain_winapi_file()
        # Load into memory the JSON data
        with open("winapi_categories.json") as file:
            print("[*] Loading winapi_categories.json file")
            JSON_DATA = json.load(file)

        for dll in sys.argv[1:]:
            # Obtain APIs from EAT of given dll(s)
            obtain_exports(dll) 

        # If hooks.c file does not exist, download it    
        obtain_hooks_file() 

        # Parse the file and create a dictionary of APIs already hooked        
        for hook in dll_exports:
            if hook not in capemon_hooks:
                generate_hooks(hook, dll_exports[hook])
        


    