####
# A python script designed to decrypt media files encrypted using the Android application
# 'AVG Photo Vault'. If script cannot idenify PIN in files it will bruteforce, this may take a while.
# Original blog post: https://theincidentalchewtoy.wordpress.com/2022/02/23/decrypting-the-avg-photo-vault/
####


## Import all required modules
import sys
import os
import glob
import xml.etree.ElementTree as ET
from hashlib import sha1
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from binascii import unhexlify
from Crypto.Cipher import AES
import filetype
from itertools import permutations

### Known constants
requiresBrute = True
patternExists = False
## Keep this file in the same folder as the script.
## It contains the PIN hash based on the 'toCharArray' conversion
pinFile = 'PasscodeWithValues.txt'
pinDict = {}

### First check if the file exists then,
### iterate through the converted PINs and assign them to the dictionary
if(os.path.exists(pinFile)):
    with open(pinFile, 'r') as pinFile:
        while True:
            _currentPIN= pinFile.readline()
            convertedPIN= pinFile.readline()
            pinDict[_currentPIN.rstrip()] = convertedPIN.rstrip()
            ### When there are no more lines, break.
            if not _currentPIN:
                pinFile.readline()
                break   
else:
    printFunc('Could not find PIN file, will now exit.', True, False, True)
    exit()

### Take arguments
##/data/data/com.antivirus
cwd = sys.argv[1]
## /sdcard/Vault
media_dir = sys.argv[2]
## output folder
output_dir = sys.argv[3]

### Print function to reduce code (slightly)
def printFunc(dataToPrint,prependDash,newLine, appendDash):
    stringToPrint = ''
    if prependDash:
        stringToPrint += ('\n------------------------------------------\n')
    stringToPrint += dataToPrint
    if appendDash:
        stringToPrint += ('\n------------------------------------------')
    if newLine:
        stringToPrint += '\n'    
    print(stringToPrint)

### Identify master encryption key
def identifyMasterKey(PIN):
    ### PBKDF2 key derivation
    derivedKey = PBKDF2(unhexlify(PIN),  masterIV, 16, count=100, hmac_hash_module=SHA1).hex()
    ### Create new instace of cipher using masterIV and derivedKey
    cipher = AES.new(bytes.fromhex(derivedKey), AES.MODE_CBC, masterIV)
    ### Decrypt the first encrypted value
    masterKey = cipher.decrypt(firstEncryptedValue)
    ### Decrypt the second encrypted value
    masterKey = cipher.decrypt(secondEncryptedValue)
    return(masterKey,derivedKey)

### Decryption function
def decryptData(encryptedInput):
    if(int.from_bytes(encryptedInput[:4], "big") == 16):
        base = 0
    else:
        base = 4     
    ### Get the IV from the file
    fileIV = encryptedInput[base + 4: base + 20 ]
    ### Get the encrypted data length
    fileSize = int.from_bytes(encryptedInput[base + 20: base + 24], "big")
    ### Get the encrypted data based on the length
    fileFull = encryptedInput[-fileSize:]
    ### Create new instance of cipher using IV from the file and master key.
    cipher = AES.new(masterKey, AES.MODE_CBC, fileIV)
    ### Decrypt the data
    decryptedData = cipher.decrypt(encryptedInput[-fileSize:])
    ### Return the decrypted value
    return(decryptedData)

### Copy the file after the file extension has been determined
def copyWithExt(dataToWrite, outputPath):
    ### Determine the correct file extension
    fileExtension = filetype.guess(dataToWrite)
    ###
    if(not fileExtension):
        fileExt = 'json'
    else:
        fileExt = fileExtension.extension
    ### Open the new file for writing
    with open ((os.path.join(outputPath + f'.{fileExt}')) , 'wb') as fileOut:
        ### Write the data to the new file
        fileOut.write(dataToWrite)
        ### Close the output file
        fileOut.close()

### Check if folder exists and create it if required        
def createFolder(folderToCreate):
    if not os.path.exists(folderToCreate):
        os.makedirs(folderToCreate)
        printFunc('*****\t\t\tCreated external directory', False, False, False)
    else:
         printFunc('*****\t\t\tDirectory already exists, skipping creation',False, False, False)

print('------------------------------------------------------------------------------')

### One key file is required for any decryption, which is the file in '.key_store'.
### If this does not exist decryption will not work 
### Check for this file first and assign variable to use later on.
try:
    if keyStore := glob.glob(media_dir + '\.data\.key_store\**')[0]:
        printFunc('Key file exists:\tDecryption Possible', False, False, False)
        printFunc('Reading relevant values for decryption', True, False, True)
        ### Open the '.key_store' file
        with open(keyStore, 'rb') as keyFile:
            keyFile = keyFile.read()
            masterIV = keyFile[8:24]
            printFunc(f'Master IV:\t\t{masterIV.hex()}', False, False, False)
            firstEncryptedValue = keyFile[24:56]
            printFunc(f'First Encrypted Value:\t{firstEncryptedValue.hex()}',False, False, False)
            secondEncryptedValue = keyFile[56:]    
            printFunc(f'Second Encrypted Value:\t{secondEncryptedValue.hex()}',False, False, False)
        printFunc('*****\t\t\tCreating output folder for decrypted files', False, False, False)
        ### If the folder doesn't exist, create it.
        createFolder(output_dir)  
except:
    printFunc('Key file not found, no decryption possible, exiting...', False, False, False)
    print('------------------------------------------------------------------------------') 
    exit()

### Check if "PinSettingsImpl.xml" exists
### This file is required for ease of decryption.
### If it does not exist bruteforce will be requried  
if settingsFile := glob.glob(cwd + '/**/PinSettingsImpl.xml', recursive=True):
    ### As settings file exists it will not require bruteforce
    requiresBrute = False
    ### Print the file has been found
    printFunc(f'Found settings file\t{settingsFile[0]}', False, False, False)
    ### Traverse the XML file
    tree = ET.parse(settingsFile[0])
    ### Set the root of the XML file
    root = tree.getroot()
    ### Will always be PIN, identify and assign to variable
    userPIN = root.findall('./string[@name="encrypted_pin"]')[0].text
    ### Print the hash
    printFunc(f'PIN Hash Identified:\t{userPIN}', False, False, False)
    ### Try statement to check if pattern exists
    try:
        ### If it exists assign to variable
        userPattern =root.findall('./string[@name="encrypted_pattern"]')[0].text
        ### If pattern present will need to be bruteforced
        patternExists = True
        printFunc(f'Pattern Hash Identified:{userPattern}', False, False, False)
    ### If it doesn't an error will be raised
    except IndexError:
        printFunc(f'*****\t\t\tNo user Pattern found in file', False, False, False)
    printFunc('', False, True, False)
### If settings file cannot be found, will require bruteforce
else:
    printFunc('*****\t\t\tCould not find settings file, will require bruteforce', False, False, True)


#### BRUTEFORCE OF PIN AND PATTERN ####    
### requiresBrute relates to if settings file doesn't exist    
if requiresBrute is False:
    printFunc('Will attempt brute force of PIN...', True, False, True)
    ### Range 0000 - 9999
    for i in range(0,10000):
        currentPIN = ('{0:04}'.format(i)).encode('utf-8')
        ## Section of code to try the hash process and assign PasscodFound if correct
        ## Compare the current PIN SHA1 and the provided AVG PIN
        if sha1(currentPIN).hexdigest() == userPIN:
            currentPIN = currentPIN.decode("utf-8")
            printFunc(f'FOUND PIN:\t\t****{currentPIN}****', False, False, True)
            pinFound = True
            javaPIN = pinDict[currentPIN]
            printFunc(f'Equivilant PIN in Java:\n{javaPIN}', False, False, False)
            printFunc(f'*****\t\t\tDeriving PBKDF2 key', True, False, True)
            ### derivedKey derivation 
            ## Derive the Primary key from the provided PIN
            keyData = identifyMasterKey(javaPIN)
            masterKey = keyData[0]
            derivedKey = keyData[1]
            printFunc(f'Derived Key:\t\t{derivedKey}', True, False, True)
            printFunc(f'Master Key:\t\t{masterKey.hex()}', True, False, True)
            break 
        else:
            continue        
        ## If the PIN is not found then exit
        if not pinFound:
            printFunc('****PIN not found, program will exit***', False, False, True)
            exit()
### Bruteforce the PIN if the file does not exist
else:
    printFunc('*****\t\t\t     Bruteforce requied and will take some time', True, False, True)
    ### Check if the '.metadata_store' store file is present
    ### Brtueforce not possible without it
    if metadataStore := glob.glob(media_dir + '\.data\.metadata_store\**')[0]:
        printFunc('Metadata file exists:\tBruteforce Possible', False, False, False)
        ### Open the '.metadata_store' file for decrypting
        with open (metadataStore, 'rb') as currentFile:
            metadataStoreContent = currentFile.read()
            ### For each PIN in the dictionary
            for pin in pinDict:
                ### Assign masterKey based on current PIN
                keyData = identifyMasterKey(pinDict[pin])
                masterKey = keyData[0]
                derivedKey = keyData[1]
                ### Decrypt data from '.key_store' file, only assign first 10 hex charectors
                decryptedData = decryptData(metadataStoreContent)[:13].hex()
                ### Check whether the decrypted data mataches the expected string
                if decryptedData == '7b2276657273696f6e223a312c':
                    printFunc(f'FOUND PIN:\t\t****{pin}****', False, False, False)
                    printFunc(f'Derived Key:\t\t{derivedKey}', False, False, False)
                    break  
    else:
        printFunc('Metadata file does not exist:\tBruteforce not Possible', True, False, True)
        exit()
        

#### BRUTEFORCE OF PATTERN IF PRESENT ####        
### If a pattern was identified in "PinSettingsImpl.xml" bruteforce it
if patternExists is True:
    printFunc('Will attempt brute force of Pattern... ', True, False, True)
    for patternLength in range(4,10):
        currentPermutation = permutations(range(0,9),patternLength)     
        for x in currentPermutation:
            currentPattern = ''.join(str(v) for v in x)
            currentPatternHex = (unhexlify(''.join([f'0{x}' for x in currentPattern])))
            if sha1(currentPatternHex).hexdigest() == userPattern:
                printFunc(f'FOUND Pattern:\t\t****{currentPattern}****', False, False, True)
                break   

#### DECRYPTING THE FILES ####
### Iterate through the directory
### Status update
printFunc('Checking for Files...', True, False, True)
for dirpath, dirnames, filenames in os.walk(media_dir):   
    ### If filenames returns true
    if((filenames)):
        ### Assign current file to 'encryptedFile' to work with
        encryptedFile = (os.path.join(dirpath, filenames[0]))
        ### If the file is within the '.key_store' directory, skip
        if('.key_store' in encryptedFile):
            continue
        ### Else, continue with the process
        else:
            printFunc(f'Found file in folder:\t\'{os.path.split(dirpath) [-1]}\'', False, False, False)
            printFunc(f'Filename:\t\t\'{filenames[0]}\'\n', False, False, False)
            printFunc(f'Attempting to decrypt:\t{filenames[0]}', False, False, False)
            ### Open file to be decrypted
            with open (encryptedFile, 'rb') as currentFile:
                ### Decrypt the data
                decryptedData = decryptData(currentFile.read())
                ### Split directory to be created
                directory = os.path.split(dirpath) [-1]
                createFolder(os.path.join(output_dir,directory))
                ### Create the decrypted file
                copyWithExt(decryptedData, os.path.join(output_dir,directory ,  filenames[0]))
                ### Close the working file
                currentFile.close()
                ### Status print
                printFunc(f'File Decrypted Successfully', True, False, True) 
print('------------------------------------------------------------------------------')                