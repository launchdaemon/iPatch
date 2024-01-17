# iPatch

A simple Python3 script that allows you to easily:

 * retrieve the command to dump the encrypted section using `lldb` once the binary has been loaded into memory decrypted.
 * overwrite the encrypted section of a Mach-O with the decrypted data dumped from a device.
 * set the cryptid to 0 to let programs know the Mach-O is not encrypted.
 * display the command to do both of the above manually with the `dd` command.

Please note, this will write to the Mach-O provided, it will not make a copy!  If you need the original, be sure to back it up first.

## Getting Started

### Prerequisites

Currently there is only one requirement for the script to properly function:

The [lief](https://lief.quarkslab.com/doc/latest/installation.html#python) Python library for parsing, modifying and abstracting the Mach-O file format.

### Installing

```
pip3 install lief
```

and git clone this repo then away you go...

## Usage
```
$ ./ipatch.py -h
usage: ipatch.py [-h] [-p PATCH | -i] [-d] macho

ipatch is designed to help overwrite the encrypted part of a Mach-O binary
with the unencrypted data dumped from a device, and patch the cryptid to 0.

positional arguments:
  macho                 Mach-O file with encrypted section

optional arguments:
  -h, --help            show this help message and exit
  -p PATCH, --patch PATCH
                        dumped, decrypted data, to overwrite encrypted section
                        of the Mach-O with
  -i, --cryptid         only patch the cryptid of the Mach-O to 0, don't
                        overwrite any data
  -d, --dd              print the commands to splice the decrypted data into
                        the Mach-O and overwrite it's cryptid with dd

```

## Example

The following shows an example of retrieving an app from an iOS device and using iPatch to help dump and then splice back in the now unencrypted seection:

 1. This could all be done on an iDevice but would require ensuring python and the lief library are correctly installed.  Also it is always handy to have the application files for further analysis so first step is idenifying where the app we want to dump is on the device:

```
iPhone:~ root# find /var/containers/Bundle/Application/ -iname "*.app" 2>/dev/null
/var/containers/Bundle/Application/1058B2CA-45CE-490E-BEA1-FE38AFE03C5A/Maps.app
-------------------------------------cut output-------------------------------------
/var/containers/Bundle/Application/4D233E52-B1A0-424E-8654-6C9E9C6199D7/Stocks.app
/var/containers/Bundle/Application/2F86045C-2CF0-4332-B47D-21D41452715A/stc pay.app
/var/containers/Bundle/Application/1C136104-AC42-4D0C-BCAC-6287663045B5/MobileCal.app
```

 2. We can then copy that on to our machine, in this case the STC Pay app, with the following, assuming `iproxy` is forwarding port 4444 to the device:

```
    $ scp -P 4444 -r root@localhost:/var/containers/Bundle/Application/2F86045C-2CF0-4332-B47D-21D41452715A . 
```

 3. On our machine, we can the run `ipatch` against the binary to get the offsets to dump the encrypted section with `lldb`:

```
    $ ipatch.py stc\ pay.app/Payload/stc\ pay.app/stc\ pay
    [+]  Checking file magic...
    [+]  Based on the magic bytes, the provided file appears to be a 64-bit Mach-O binary
    [+]  To dump the binary unencrypted, launch the app with debugserver on your iDevice, connect to it with lldb from your host and run 'image list'
    [+]  This will give you the offset in memory of the binary.
    [+]  Dump the unencrypted binary from lldb with:
            memory read --force --outfile /tmp/stc pay.dumped --binary --count 0xa3c000 [offeset from image command]+0x8000
````

 4. Having copied the original binary from the app bundle to our current working directory, we can give `ipatch` that along with the dumped section to splice it back in:

```
    $ ipatch.py stc\ pay -p /tmp/stc\ pay.dumped 
    [+]  Checking file magic...
    [+]  Based on the magic bytes, the provided file appears to be a 64-bit Mach-O binary
    [+]  Proceeding to attempt to patch the binary /home/jonathan/Projects/STC Pay/temp/stc pay...
    [+]  The binary appears to be encrypted
    [+]  Now proceeding to overwrite the encrypted section at offset0x8000with the data provided
    [+]  The size of the encrypted section in the binary is 10731520
    [+]  The size of the file to overwrite the encrypted section with is 10731520
    [+]  The sizes match
    [+]  Overwriting the encrypted section of the binary with provided data...
    [+]  Unencrypted data written to Mach-O
    [+]  Setting the cryptid value to 0 so the Mach-O is not still seen as encrypted
```

 5. Congratualte yourself, make a coffee and open the now unencrypted binary in your favourite disassembler.

## LC_ENCRYPTION_64_INFO

This is the load command in a Mach-O which contains information about the encrypted section of the binary.

It is defined in Apple's [source code](https://opensource.apple.com/source/xnu/xnu-6153.81.5/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) as:

	#define	LC_ENCRYPTION_INFO_64 0x2C /* 64-bit encrypted segment information */

	 * The encryption_info_command_64 contains the file offset and size of an
	 * of an encrypted segment (for use in x86_64 targets).
	 */
	struct encryption_info_command_64 {
	   uint32_t	cmd;		/* LC_ENCRYPTION_INFO_64 */
	   uint32_t	cmdsize;	/* sizeof(struct encryption_info_command_64) */
	   uint32_t	cryptoff;	/* file offset of encrypted range */
	   uint32_t	cryptsize;	/* file size of encrypted range */
	   uint32_t	cryptid;	/* which enryption system,
					   0 means not-encrypted yet */
	   uint32_t	pad;		/* padding to make this struct's size a multiple
					   of 8 bytes */
	};

There is the 32-bit equivalent, `LC_ENCRYPTION_INFO`, but that has been ignored for now as 32-bit devices are no longer supported by Apple.

An example of what the load command would look like if you opened a Mach-O in a hex editor:

	2C 00 00 00 18 00 00 00 00 40 00 00 00 80 16 00 01 00 00 00 00 00 00 00

So based on the definition above we can see that for the Mach-O this was taken from:

| Section   | Data        | Description                                             |
| :-----    | -----:      | -----:                                                  |
| cmd type  | 2C 00 00 00 | LC_ENCRYPTION_INFO_64 as defined in the source code     |
| cmdsize   | 18 00 00 00 | 24 bytes (6 x 32 bit data types)                        |
| cryptoff  | 00 40 00 00 | The offset of the encrypted section of the Mach-O       |
| cryptsize | 00 80 16 00 | The size of the encrypted section                       |
| cryptid   | 01 00 00 00 | Indicating the Mach-O is encrypted                      |
| pad       | 00 00 00 00 | padding to make this struct's size a multiple of 8 bytes|

## Contribute

Feel free to make any suggestions for improvement or requests and forgive the terrible Python.

## TODO

See what happens when Apple release their ARM based Macs and whether we end up with fat binaries or anything else to consider when analysing the binary.