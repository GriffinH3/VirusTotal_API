'''
J.Griffin Harrington
Virus Total Api
December 9, 2020
'''
from tkinter.filedialog import askopenfilename
from tkinter import Tk
import json
import hashlib
import os
import sys
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi


# You will need to obtain an API Key from Virus Total
API_KEY = 'Enter VirusTotal API HERE'
print("Virus Total API")
user_input = input("\nWould you like to start the program? (Y/N): ")
if not(user_input.lower() == "y"):
    print("Exiting the Program...")
    sys.exit()

print("You will be prompted to select a file to be checked.")
time.sleep(2)

Tk().withdraw()
filename = askopenfilename()
print(filename)

if not(os.path.isfile(filename)):
    user_response = input("\nYou didn't select a file would you like to try again?(Y/N): ")
    if not(user_response.lower() == "y"):
        print("Exiting the Program...")
        sys.exit()    
    
#Hashes the file to sumbit to virustotal 
SAMPLE_MD5 = hashlib.md5(b'filePath').hexdigest()

#Checks virustotal
vt = VirusTotalPublicApi(API_KEY)

response =  vt.get_file_report(SAMPLE_MD5)
print (json.dumps(response, sort_keys=False, indent=4))
print()
print("Goodbye")