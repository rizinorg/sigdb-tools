# SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import sys
import glob
import os
import threading
import subprocess
import multiprocessing

DESCRIPTION='Rizin windows .lib unpacker'
EPILOG='''
This tool unpacks windows .lib files

The output of the tools will be in the same folder as the actual lib.
Example:
	# Call the script to unpack all the .lib files in the folder (recursively)
	$ python generate-obj-from-lib.py --input /path/to/dir

Details:
	This tool will unpack all the .lib files found in the input path

	Lets say for example there is a lib called rpcproxy.lib in /mnt/masm32/v10/,
	then the output of all the object files will be indide /mnt/masm32/v10/rpcproxy.lib.ext

	The reason to use this script instead of doing this manually is because
	lib files can contain full paths like d:\\bla\\bla\\bla\\file.obj and when unpacking
	the ar tool will sometimes complain because the path does not exist.
	
	What the script mainly does is to ensure before unpacking that such path does exists
	and only then unpack the lib file.

	It is suggested to use this tool with the generate-pat-from-obj.py to create a proper
	sigdb folder structure automatically.
'''

class Counter(object):
    def __init__(self, value=0):
        self.val = multiprocessing.RawValue('i', value)
        self.lock = multiprocessing.Lock()

    def increment(self):
        with self.lock:
            self.val.value += 1

    def value(self):
        with self.lock:
            return self.val.value

IS_VERB = False
PADDING = ""
CURRENT = Counter()
TOTAL = 0

def system(cmd):
	output = ""
	with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True) as process:
		output = process.communicate()[0].decode("utf-8")
		if process.returncode != 0:
			print("{} exit with {}".format(cmd, process.returncode))
			sys.exit(1)
	return output.strip()

def unpack_lib(file):
	name = os.path.basename(file)
	extd = file + '.ext'
	global IS_VERB, RZ_SIGN, PADDING, TOTAL, CURRENT
	CURRENT.increment()
	if IS_VERB:
		print("[{}|{}] parsing {}".format(CURRENT.value(), TOTAL, name), flush=True)
	else:
		print("        {}\r[{}|{}] parsing {}".format(PADDING, CURRENT.value(), TOTAL, name), end='\r', flush=True)

	if not os.path.isdir(extd):
		os.mkdir(extd)

	strings = system('ar t \"{0}\" | grep -i ".obj$" | sort | uniq'.format(file))
	for sub1 in strings.split('\n'):
		sub1 = sub1.strip()
		if " " in sub1:
			continue
		sub = sub1.replace('\\', '/')
		sub = os.path.abspath(extd + "/" + sub1)
		sub = os.path.dirname(sub)
		os.makedirs(sub, exist_ok=True)

	os.system("cd \"{0}\" ; ar x \"{1}\" 2>&1 | grep -v -i 'illegal output pathname for archive member\\|dll:'".format(extd, file))


def main():
	parser = argparse.ArgumentParser(usage='%(prog)s [options]', description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-v', '--verbose', default=False, help='verbose', action='store_true')
	parser.add_argument('-i', '--input', help='input directory to scan for .lib files')
	args = parser.parse_args()

	if len(sys.argv) == 1 or \
		len(args.input) < 1:
		parser.print_help(sys.stderr)
		sys.exit(1)

	global IS_VERB, TOTAL, PADDING
	IS_VERB = args.verbose

	print("input dir:", args.input)
	os.chdir(args.input)

	files_input = []
	files_input += glob.glob('**/*.lib', recursive=True)
	files_input += glob.glob('**/*.Lib', recursive=True)
	files_input += glob.glob('**/*.LIB', recursive=True)
	files_input += glob.glob('**/*.LIb', recursive=True)

	files_input = list(set(files_input))

	TOTAL = len(files_input)
	if TOTAL < 1:
		print("cannot find any *.lib files in '{}'".format(args.input))
		sys.exit(1)
	print("found", TOTAL, "file to ingest\n")

	maxlen = 0
	mapped = []
	for file in files_input:
		file_in = os.path.abspath(file)
		if os.path.exists(file_in) and not os.path.isdir(file_in):
			maxlen = max(maxlen, len(os.path.basename(file)))
			mapped.append(file_in)

	PADDING = " " * maxlen

	with multiprocessing.Pool() as pool:
		pool.map(unpack_lib, mapped)
	#for f in mapped:
	#	unpack_lib(f)
	print("\ndone.")

if __name__ == '__main__':
	main()
