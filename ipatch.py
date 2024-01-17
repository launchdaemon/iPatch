import os
import sys
import struct
import argparse
import lief

MH_MAGIC_64    = b'\xFE\xED\xFA\xCF'
MH_CIGAM_64 = struct.pack('<L', struct.unpack('>L', MH_MAGIC_64)[0])

def parse_args():
    ap = argparse.ArgumentParser(prog = 'ipatch.py',
                                 description = 'ipatch is designed to help overwrite the encrypted part of a Mach-O binary with the unencrypted data dumped from a device, and patch the cryptid to 0.')
    ap.add_argument('macho', help='Mach-O file with encrypted section')
    group = ap.add_mutually_exclusive_group()
    group.add_argument('-p', '--patch', nargs=1, type=str, help='dumped, decrypted data, to overwrite encrypted section of the Mach-O with')
    group.add_argument('-i', '--cryptid', action ='store_true', default=False, help='only patch the cryptid of the Mach-O to 0, don\'t overwrite any data')
    ap.add_argument('-d', '--dd', action ='store_true', default=False, help='print the commands to splice the decrypted data into the Mach-O and overwrite it\'s cryptid with dd')

    args = ap.parse_args()

    if (os.path.exists(args.macho)):
        checkFileMagic(args.macho)
        binary = lief.parse(args.macho)
        if (args.cryptid):
            patchCryptID(binary, args.macho)
        elif ((not(args.patch == None)) and (os.path.exists(args.patch[0]))):
            if (args.dd):
                printDD(args.macho, args.patch, binary)
            else:
                print ('[+]  Proceeding to attempt to patch the binary ' + args.macho + "...")
                checkEncryption(binary)
                checkPatchSize(binary, args.patch)
                patchMachO(args.macho, args.patch, binary.encryption_info.crypt_offset)
                patchCryptID(binary, args.macho)
        elif ((args.patch == None) and (args.dd)):
            print('[+]  Please provide the path to the decrypted data for the dd command to manually patch ' + args.macho)
        elif (binary.encryption_info.crypt_id == 1):
            print('[+]  To dump the binary unencrypted, launch the app with debugserver on your iDevice, connect to it with lldb from your host and run \'image list\'')
            print('[+]  This will give you the offset in memory of the binary.')
            print('[+]  Dump the unencrypted binary from lldb with:\n')
            print('         memory read --force --outfile /tmp/' + os.path.basename(args.macho) + '.dumped --binary --count ' + hex(binary.encryption_info.crypt_size) + ' [offeset from image command]+' + hex(binary.encryption_info.crypt_offset) + '\n')
        elif (binary.encryption_info.crypt_id == 0):
            print('[+]  The Mach-O is not encrypted.  Please provide an encrypted Mach-O or an additional option')
    else:
        print ('[+]  Please provide a valid paths to a Mach-O file and a file with the unencrypted data')

def checkFileMagic(macho):
    print('[+]  Checking file magic...')
    fileMagic = open(macho, 'rb').read(4)
    if ((fileMagic == MH_MAGIC_64) or (fileMagic == MH_CIGAM_64)):
        print('[+]  Based on the magic bytes, the provided file appears to be a 64-bit Mach-O binary')
    else:
        print('[+]  Are you sure you provided a valid Mach-O file?  The magic bytes suggest otherwise...')
        exit()

def checkEncryption(binary):
    if (not (binary.has_encryption_info)):
        print ('[+]  The binary does not appear to be encrypted')
        print ('[+]  There is no encrypted data to patch, what are you trying to do?')
    elif ((binary.has_encryption_info) and (binary.encryption_info.crypt_id == 0)):
        print ('[+]  The binary includes an LC_ENCRYPTION_INFO_64 load command but it\'s cryptid is set to \'0\' suggesting it is not actually encrypted')
        response = input('[+]  An offset is still specified that we can write to but are you sure you want to? (y/n)')
        if (not(response.lower() == 'y')):
            exit()
    elif (binary.has_encryption_info):
        print ('[+]  The binary appears to be encrypted')
        print ('[+]  Now proceeding to overwrite the encrypted section at offset ' + hex(binary.encryption_info.crypt_offset) + ' with the data provided')

def checkPatchSize(binary, patch):
    print('[+]  The size of the encrypted section in the binary is ' + str(binary.encryption_info.crypt_size))
    print('[+]  The size of the file to overwrite the encrypted section with is ' + str(os.path.getsize(patch[0])))
    if (binary.encryption_info.crypt_size == os.path.getsize(patch[0])):
        print('[+]  The sizes match')
        print('[+]  Overwriting the encrypted section of the binary with provided data...')
    else:
        print('[+]  The size of the encrypted section of the binary does not match the size of the data provided')
        print('[+]  This will corrupt the Mach-O, exiting now...')

def patchMachO(macho, patch, offset):
    decrypted = open(patch[0], 'rb').read()
    with open(macho, "r+b") as original:
        original.seek(offset)
        original.write(decrypted)
    print('[+]  Unencrypted data written to Mach-O')

def patchCryptID(binary, path):
    if (binary.encryption_info.crypt_id == 0):
        print('[+]  ' + os.path.basename(path) + '\'s cryptid is already set to 0')
    else:
        print('[+]  Setting the cryptid value to 0 so the Mach-O is not still seen as encrypted')
        with open(path, "r+b") as macho:
            macho.seek(binary.encryption_info.command_offset + 16)
            macho.write(bytes([0]))

def printDD(macho, patch, binary):
    print('[+]  To splice the decrypted data back in to the original Mach-O, use the following command:\n')
    print('        dd seek=' + str(binary.encryption_info.crypt_offset) + ' bs=1 conv=notrunc if=' + patch[0] + ' of=' + macho + '\n')
    print('[+]  To write 0 to the cryptid, letting programs know the Mach-O is not encrypted, run:\n')
    print('        echo -ne \'\\x00\' | dd of=' + macho + ' bs=1 seek=' + str(binary.encryption_info.command_offset + 16) + ' count=1 conv=notrunc' + '\n')

def main():
    parse_args()

if __name__== "__main__":
    main()