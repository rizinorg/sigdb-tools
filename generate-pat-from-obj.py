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
import json
import time
from datetime import timedelta

DESCRIPTION='Rizin (source) signature database maker for .o/.lo/.obj files'
EPILOG='''
This tool generates .pat files from .o/.lo/.obj in a sigdb folder structure
Example:
	# Unpack first an object archive inside a folder
	$ mkdir object-dir
	$ cd object-dir
	$ ar /path/to/libsomething.a
	$ cd ..

	# Create a temporary folder where to store all the results in sigdb format
	$ mkdir sigdb-tmp

	# Call the script to generate all the pat files in sigb-db folder structure
	# the script will call rz-bin and rz-sign to create the pat files correctly
	$ python generate-pat-from-obj.py --input object-dir --output sigdb-tmp
'''
RZ_BIN  = "rz-bin"
RZ_SIGN = "rz-sign"


class Counter(object):
    def __init__(self):
        self.val = multiprocessing.RawValue('i', 0)
        self.lock = multiprocessing.Lock()

    def increment(self):
        with self.lock:
            self.val.value += 1

    def value(self):
        with self.lock:
            return self.val.value

class Timer(object):
	def __init__(self, total, value=0):
		self.total = total
		self.count = Counter()
		self.lock = multiprocessing.Lock()
		self.start = time.time()

	def info(self):
		with self.lock:
			self.count.increment()
			value = self.count.value()
			elapsed = int(time.time() - self.start)
			timeleft = ((self.total * elapsed) / value) - elapsed
			perc = int((value * 100) / self.total)
			remain = timedelta(seconds=timeleft)
			current = timedelta(seconds=elapsed)
			remain = str(remain).split('.')[0]
			current = str(current).split('.')[0]
			return f"{remain} {current} ({perc:3d}%)"


class Locator(object):
	def __init__(self, input, output, library):
		super(Locator, self).__init__()
		self.input = os.path.abspath(input)
		self.output = os.path.abspath(output) if len(output) > 0 else ""
		self.library = library
		self.lock = multiprocessing.Lock()

	def pat_file(self, source, btype, arch, bits):
		with self.lock:
			if len(self.output) < 1:
				return source + '.pat'
			name = os.path.basename(source)
			subpath = os.path.abspath(source)[len(self.input) + 1:]
			dirp = os.path.join(self.output, btype, arch, bits, self.library, subpath)
			dirp = os.path.dirname(dirp)
			os.makedirs(dirp, exist_ok=True)
			return os.path.join(dirp, name + '.pat')


class Logger(object):
	def __init__(self, total, verbose):
		super(Logger, self).__init__()
		self.verbose = verbose
		self.timer = Timer(total)
		self.padding = "                "
		self.lock = multiprocessing.Lock()

	def set_padding(self, maxlen):
		with self.lock:
			self.padding = "                " + (" " * maxlen)

	def level(self):
		with self.lock:
			if self.verbose:
				return 5
			return 6

	def print(self, name):
		with self.lock:
			info = self.timer.info()
			if self.verbose:
				print(f"{info} parsing {name}", flush=True)
			else:
				print(f"{info} parsing {name}", end='\r', flush=True)

def system(cmd):
	output = ""
	with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True) as process:
		output = process.communicate()[0].decode("utf-8")
		if process.returncode != 0:
			print(f"{cmd} exit with {process.returncode}")
			return ""
	return output.strip()

def safe_get(o, k, d=None):
	if k in o:
		return str(o[k])
	return d

class SigMake(object):
	def __init__(self, file):
		super(SigMake, self).__init__()
		self.name = os.path.basename(file)
		self.file = file

	def worker(sm):
		sm.generate()

	def bin_info(self):
		output = system("{0} -Ij '{1}'".format(RZ_BIN, self.file))
		if len(output) < 1:
			return None, None, None
		o = json.loads(output).get("info", {})
		return o.get("bintype"), o.get("arch"), str(o.get("bits"))

	def generate(self):
		logger.print(self.name)
		bintype, arch, bits = self.bin_info()
		if bintype == None or arch == None:
			return
		path_file = locator.pat_file(self.file, bintype, arch, bits)
		if os.path.exists(path_file):
			return
		log_level = logger.level()
		os.system("{0} -q -a -e 'flirt.node.optimize=0' -e 'bin.demangle=false' -e 'log.level={1}' -o '{2}' '{3}'".format(RZ_SIGN, log_level, path_file, self.file))

locator = None
logger = None

def main():
	parser = argparse.ArgumentParser(usage='%(prog)s [options]', description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-v', '--verbose', default=False, help='verbose', action='store_true')
	parser.add_argument('-i', '--input', default="", help='input directory to scan for .o/.lo files')
	parser.add_argument('-o', '--output', default="", help='output directory (optional but requires -l/--libname)')
	parser.add_argument('-l', '--libname', default="", help='library name in the outdir (optional)')
	parser.add_argument('-s', '--rz-sign', default='rz-sign', help='rz-sign binary path')
	parser.add_argument('-b', '--rz-bin', default='rz-bin', help='rz-bin binary path')
	args = parser.parse_args()

	if len(sys.argv) == 1 or \
		len(args.input) < 1 or \
		len(args.rz_sign) < 1 or \
		len(args.rz_bin) < 1:
		parser.print_help(sys.stderr)
		sys.exit(1)

	global RZ_SIGN, RZ_BIN, locator, logger
	RZ_SIGN = args.rz_sign
	RZ_BIN = args.rz_bin
	locator = Locator(args.input, args.output, args.libname)

	print("input dir:", args.input)
	os.chdir(args.input)

	files_input = []
	files_input += glob.glob('**/*.o', recursive=True)
	files_input += glob.glob('**/*.lo', recursive=True)
	files_input += glob.glob('**/*.obj', recursive=True)

	total = len(files_input)
	if total < 1:
		print("cannot find any *.o or *.lo files in '{}'".format(args.input))
		sys.exit(1)
	print("found", total, "file to ingest")

	logger = Logger(total, args.verbose)

	maxlen = 0
	mapped = []
	for file in files_input:
		file_in = os.path.abspath(file)
		sigmake = SigMake(file_in)
		maxlen = max(maxlen, len(sigmake.name))
		mapped.append(sigmake)

	logger.set_padding(maxlen)

	with multiprocessing.Pool() as pool:
		pool.map(SigMake.worker, mapped)
	print("\ndone.")

if __name__ == '__main__':
	main()
