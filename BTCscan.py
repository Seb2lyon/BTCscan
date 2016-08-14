#    Copyright 2014 Chris Cohen
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# LIMITATIONS - Does not search encrypted / compressed items.
# LIMITATIONS - Does not search for pure hex addresses/keys. 
# LIMITATIONS - Does not search for testnet items only mainnet.
# LIMITATIONS - Most likely only works on Windows / Python 3

# TO DO - mini private keys https://en.bitcoin.it/wiki/Mini_private_key_format
# TO DO - BIP39 Mnemonic - "cake apple borrow silk endorse fitness top denial coil riot stay wolf luggage oxygen faint major edit measure invite love trap field dilemma oblige"

# I would be very interesting in hearing from you if you find this program of use. 
# Email:     chris.w.cohen@gmail.com
# Donations: 1BnvsBZcyVxF8L8HboUcDc2mAUu9K2qsTe
# Accompanying Article: https://articles.forensicfocus.com/2015/01/16/forensics-bitcoin/

import re
import sys
import os
import time
import getopt
from hashlib import sha256
from mmap import ACCESS_READ, mmap

# Global Variables
version_number = "0.9"
website = "https://gist.github.com/chriswcohen/7e28c95ba7354a986c34"
donation_address = "1BnvsBZcyVxF8L8HboUcDc2mAUu9K2qsTe"
author = "Chris COHEN (chris.w.cohen@gmail.com)"

file_to_examine = r"" # The r here makes it a raw string, as \u is an escape character
shortest_length = 25
base58_passed_found = 0
files_examined = 0
total_file_size = 0
quick_mode = False
unicode_mode = False
nonunicode_mode = False

# Bitcoin (Bitcoin pubkey hash) 26-35 Base58Check chars, beginning with the number 1 
# Pay to script hash (P2SH) 26-35 Base58Check chars, beginning with the number 3
# Unicode Bitcoin or P2SH address
# BIP38 Encrypted Private Key - 58 characters always starting with '6P'
# Unicode BIP38 Encrypted Private Key - 58 characters always starting with '6P'
# Private key - uncompressed public keys - 51 characters always starting with the number 5 
# Private keys - compressed public keys - 52 characters always starting with a capital L or K on mainnet
# BIP32 HD wallet private node key - 111-112 Base58Check characters starting with xprv
# BIP32 HD wallet public node key - 111-112 Base58Check characters starting with xpub

quick_group = [True, True, 
               True, True, 
               True, True, 
               True, True, 
               True, True,
               False, False,
               False, False]

patterns_group = [b'1[a-km-zA-HJ-NP-Z1-9]{25,34}',
                  b'1\x00([a-km-zA-HJ-NP-Z1-9]\x00){25,34}',
                  b'3[a-km-zA-HJ-NP-Z1-9]{25,34}',
                  b'3\x00([a-km-zA-HJ-NP-Z1-9]\x00){25,34}',
                  b'6P[a-km-zA-HJ-NP-Z1-9]{56}',
                  b'6\x00P\x00([a-km-zA-HJ-NP-Z1-9]\x00){56}',
                  b'5[a-km-zA-HJ-NP-Z1-9]{50}',
                  b'5\x00([a-km-zA-HJ-NP-Z1-9]\x00){50}',
                  b'[KL][a-km-zA-HJ-NP-Z1-9]{51}',
                  b'[KL]\x00([a-km-zA-HJ-NP-Z1-9]\x00){51}',
                  b'xprv[a-km-zA-HJ-NP-Z1-9]{107,108}',  
                  b'x\x00p\x00r\x00v\x00([a-km-zA-HJ-NP-Z1-9]\x00){107,108}',
                  b'xpub[a-km-zA-HJ-NP-Z1-9]{107,108}',  
                  b'x\x00p\x00u\x00b\x00([a-km-zA-HJ-NP-Z1-9]\x00){107,108}']

byte_length_group = [25, 25, 25, 25, 43, 43, 37, 37, 38, 38, 82, 82, 82, 82]

names_group = ['Bitcoin address', 
               'Bitcoin address',
               'Bitcoin P2SH',
               'Bitcoin P2SH',
               'BIP38 Encrypted Private Key',
               'BIP38 Encrypted Private Key',
               'WIF Private key, uncompressed public keys',
               'WIF Private key, uncompressed public keys',
               'WIF Private key, compressed public keys',
               'WIF Private key, compressed public keys',
               'BIP32 HD walllet private node',
               'BIP32 HD walllet private node',
               'BIP32 HD walllet public node',
               'BIP32 HD walllet public node']
               
unicode_group = [False, True, 
                 False, True, 
                 False, True, 
                 False, True, 
                 False, True,
                 False, True,
                 False, True]

def process_grep_match(match, byte_length):
    "Performs actions on the found addresses"
    try:
        result = check_base58check(match, byte_length)
    except OverflowError as e:
        return False
    except ValueError as e:
        return False
    except TypeError as e:
        return False
    except  ValueError as e:
        return False
    return result

# The procedures check_base58check and decode_base58 were initially from:
# http://rosettacode.org/wiki/Bitcoin/address_validation#Python
# released under the GNU Free Documentation License 1.2
digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def check_base58check(bc, byte_length):
    bcbytes = decode_base58(bc, byte_length) 

    if bcbytes == None:
        return False

    return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]

def decode_base58(bc, length):
    n = 0

    # converts the Base58 encoded string to decimal
    for char in bc:
        n = n * 58 + digits58.index(char)

    # At this point this script returns it as bigendian bytes, which is the length which has been set below
    return n.to_bytes(length, 'big')

def examine_file(file_2_examine):
    "The main processing loop, which examines the passed file"

    global files_examined       # this ensures that the global variable is used
    global grep_matches_found   # this ensures that the global variable is used
    global total_file_size      # this ensures that the global variable is used
    global base58_passed_found  # this ensures that the global variable is used

    if not os.path.exists(file_2_examine):
        sys.stdout.write(file_2_examine + " : Not found.")
        return

    file_size = os.path.getsize(file_2_examine)
    sys.stdout.write("\r                                                                         ")
    # If filename contains unprintable characters, may cause error, hence error catching below
    try:
        sys.stdout.write("\rScanning: " + file_2_examine + " (" + str(file_size) + " bytes)" + "\n")
    except UnicodeEncodeError:
        sys.stdout.write("\rScanning: <filename contains unprintable characters> (" + str(file_size) + " bytes)" + "\n")

    if file_size < shortest_length:
        sys.stdout.write("File too short")
        return

    files_examined += 1
    total_file_size = total_file_size + file_size

    try:
        with open(file_2_examine, 'rb') as f, mmap(f.fileno(), 0, access=ACCESS_READ) as mm:

            for x in range(0, len(patterns_group)):
                # if quick mode selected, then check quick group whether to run this search or not
                if (quick_mode == True) and (quick_group[x] == False):
                    continue

                # if unicode mode selected, then check unicode_group whether to run this search or not
                if (unicode_mode == True) and (unicode_group[x] == False):
                    continue

                # if non-unicode mode selected, then check unicode_group whether to run this search or not
                if (nonunicode_mode == True) and (unicode_group[x] == True):
                    continue

                # Clear previously printed entry
                sys.stdout.write("\r                                                                         ")
                if unicode_group[x] == True:
                    sys.stdout.write("\rSearching for: " + names_group[x] + " (unicode)")
                    sys.stdout.flush()
                else: 
                    sys.stdout.write("\rSearching for: " + names_group[x])
                    sys.stdout.flush()

                for match in re.finditer(patterns_group[x], mm):
                    s = match.start()
                    e = match.end()
                    grep_match_found = mm[s:e].decode("utf-8")

                    # if unicode remove every other byte
                    if unicode_group[x] == True:
                        grep_match_found = grep_match_found[::2]

                    if process_grep_match(grep_match_found, byte_length_group[x]) == True:
                        # GREP match has passed the Base58Check 
                        base58_passed_found += 1
                        output_file.write('"' + str(grep_match_found) + '","' + file_2_examine + '","' + str(s) + '","' + names_group[x] + '","' + str(unicode_group[x]) +'"\n')

        f.close()
        mm.close()
    except PermissionError as e:
        sys.stdout.write("PremissionError: %s" % str(e))

def usage():
    "Prints how to use the program to the command line"
    info()
    sys.stdout.write("\n")
    sys.stdout.write("Searches a file or all files within a folder including subfolders for Bitcoin\n")
    sys.stdout.write("related Base58Check encoded strings.\n")
    sys.stdout.write("\n")
    sys.stdout.write(os.path.basename(__file__) + " [-i/--input=][drive:][path][filename] [args]\n")
    sys.stdout.write("\n")
    sys.stdout.write("-i / --input       Specifies drive, directory, and/or files to search\n")
    sys.stdout.write("-q / --quick       Quick mode, does not search BIP32 HD walllet keys\n")
    sys.stdout.write("-u / --unicode     Unicode mode, only search for unicoded items\n")
    sys.stdout.write("-n / --nonunicode  Non-unicode mode, only search for non-unicoded items\n")
    sys.stdout.write("-h / --help        Prints this page\n")
    sys.stdout.write("\n")
    sys.stdout.write("Examples:\n")
    sys.stdout.write("   " + os.path.basename(__file__) + " -i JED-01.dd\n")
    sys.stdout.write('   ' + os.path.basename(__file__) + ' -input="C:\\folder\\"\n')
    sys.stdout.write('   ' + os.path.basename(__file__) + ' --quick -u -i memory.dat\n')

def info():
    "Prints info about program to the command line"
    sys.stdout.write("\n")
    sys.stdout.write("BTCscan " + version_number + " by "+ author + "\n")
    sys.stdout.write("\n")
    sys.stdout.write("Website: " + website + "\n")
    sys.stdout.write("Donations: " + donation_address + "\n")
    sys.stdout.write("\n")
    sys.stdout.write("If you find BTCscan to be of use to yourself, organisation or company then I\n")
    sys.stdout.write("politely ask that you write me a very short email letting me know how it\n")
    sys.stdout.write("worked out for you. This information will never be published - it is solely\n")
    sys.stdout.write("for my own personal interest.\n\n")

####################################
# MAIN BODY OF PROGRAM STARTS HERE #
####################################
if __name__ == "__main__":
    ### CHECK ARGUMENTS PASSED ###
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:qun", ["help", "input=","quick","unicode","nonunicode"])
    except getopt.GetoptError:          
        usage()                         
        sys.exit(2)         
    for opt, arg in opts:                
        if opt in ("-h", "--help"):      
            usage()                     
            sys.exit()
        elif opt in ("-q", "--quick"):
            quick_mode = True
        elif opt in ("-u", "--unicode"):
            unicode_mode = True
        elif opt in ("-n", "--nonunicode"):
            nonunicode_mode = True
        elif opt in ("-i", "--input"): 
            file_to_examine = arg
            file_to_examine = file_to_examine.rstrip('\\') # strip off back slash if last character
            file_to_examine = file_to_examine.rstrip('"') # strip off quote if last character - not sure why this happens
            if not os.path.isfile(file_to_examine) and not os.path.isdir(file_to_examine):
                sys.stdout.write("That file or folder does not exist")
                sys.exit(2)

    if file_to_examine == "":
        usage()
        sys.exit()

    # Print info information
    info()
    sys.stdout.write("\n")
    case_name = input("Case name: ")
    sys.stdout.write("\n")
    start_time = time.time()

    ## CREATE OUTPUT FILE ###
    output_file = open(case_name + "-" + time.strftime("%d%m%Y-%H%M%S") + ".csv", "w")
    output_file.write("Hit,File,Offset,Type,Unicode\n")

    if os.path.isfile(file_to_examine):
        examine_file(file_to_examine)

    elif os.path.isdir(file_to_examine):
        rootdir = file_to_examine
        for subdir, dirs, files in os.walk(rootdir):
            for file in files:
                examine_file(os.path.join(subdir, file))

    output_file.close()  

    duration = time.time() - start_time
    # clear last printed "Checking for... " entry
    sys.stdout.write("\r                                                                         ")
    sys.stdout.write("\n" + str(files_examined) + " files examined\n")
    sys.stdout.write(str(base58_passed_found) + " Base58Check matches found\n")
    sys.stdout.write(str(total_file_size) + " bytes examined\n")
    sys.stdout.write(str('%.2f'%duration) + " seconds processing time\n")

    if duration > 0.1:
        sys.stdout.write("Processed " + str('%.2f'%((total_file_size/duration)/1000000)) + " MB/s\n")    

    sys.stdout.write("\n")
    # if no items found - delete file
    if base58_passed_found == 0:
        os.remove(output_file.name)
        sys.stdout.write("No matches found\n")
    else:
        sys.stdout.write("Output file: " + output_file.name + "\n")