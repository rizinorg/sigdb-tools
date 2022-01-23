# SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import sys
import tempfile
import os
import subprocess
import multiprocessing

SRC_LIB = "libc.a"
OBJ_DIR = "o-files"
RZ_SIGN = "rz-sign"
IS_VERB = False
DESCRIPTION='Rizin (source) signature database maker for deb files'
EPILOG=''
DEBCURRN=0
DEBTOTAL=0

def system(cmd):
	output = ""
	with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True) as process:
		output = process.communicate()[0].decode("utf-8")
		if process.returncode != 0:
			print("{} exit with {}".format(cmd, process.returncode))
			sys.exit(1)
	return output.strip()

def system_die(cmd):
	ret = os.system(cmd)
	if ret != 0:
		print("{} exit with {}".format(cmd, ret))
		sys.exit(1)

class SigMake(object):
	def __init__(self, file_in, file_out):
		super(SigMake, self).__init__()
		self.file_in = file_in
		self.file_out = file_out

	def worker(sm):
		sm.generate()

	def generate(self):
		global IS_VERB, RZ_SIGN
		log_level=6
		if IS_VERB:
			print('Generating signature for {} in {}'.format(os.path.basename(self.file_in), os.path.basename(self.file_out)))
			log_level=5
		os.system("{} -q -a -e 'flirt.node.optimize=0' -e 'bin.demangle=false' -e 'log.level={}' -o '{}' '{}'".format(RZ_SIGN, log_level, self.file_out, self.file_in))

class Deb(object):
	def __init__(self, file):
		super(Deb, self).__init__()
		self.file = file

	def create_pac(self, out_dir):
		global DEBCURRN
		DEBCURRN += 1
		print('[{}|{}] Unpacking & sigmake for {}'.format(DEBCURRN, DEBTOTAL, self.file))
		os.system("sha1sum '{}' > '{}'".format(self.file, os.path.join(out_dir, "hash.txt")))
		cwd = os.getcwd()
		with tempfile.TemporaryDirectory() as tmpdir:
			os.chdir(tmpdir)
			system_die("ar x '{}'".format(self.file))
			system_die("tar xf data.tar.*")
			output = system("find . -name '{}' -type f".format(SRC_LIB))
			if len(output) < 1:
				print('cannot find', SRC_LIB)
				os.chdir(cwd)
				return
			filepath = os.path.abspath(output.strip())
			os.mkdir(OBJ_DIR)
			os.chdir(OBJ_DIR)
			system_die("ar x '{}'".format(filepath))
			files = os.listdir()
			if len(files) < 1:
				print("no files were unpacked from", filepath)
				sys.exit(1)
			self._run_threaded(files, out_dir)
		os.chdir(cwd)

	def _run_threaded(self, files, out_dir):
		mapped = []
		for file in files:
			if not file.endswith(".o") and not file.endswith(".lo"):
				print("WARNING: unknown file spotted in unpacked .a:", file)
				continue
			file_in = os.path.abspath(file)
			file_out = os.path.join(out_dir, os.path.basename(file) + ".pat")
			mapped.append(SigMake(file_in, file_out))

		with multiprocessing.Pool() as pool:
			pool.map(SigMake.worker, mapped)

class Library(object):
	def __init__(self, name):
		super(Library, self).__init__()
		self.name = name
		self.distros = {}

	def create(self, arch_path):
		for distro in self.distros:
			idx = 0
			for deb in self.distros[distro]:
				idx += 1
				lpath = os.path.join(arch_path, self.name, distro, '{}'.format(idx))
				if not os.path.isdir(lpath):
					os.makedirs(lpath)
				deb.create_pac(lpath)

	def add(self, distro, deb):
		if distro not in self.distros:
			self.distros[distro] = []
		self.distros[distro].append(deb)
		
class Arch(object):
	def __init__(self, name):
		super(Arch, self).__init__()
		self.name = name
		self.libraries = {}

	def create(self, db_dir):
		apath = os.path.join(db_dir, self.name)
		if not os.path.isdir(apath):
			os.mkdir(apath)
		for libname in self.libraries:
			self.libraries[libname].create(apath)

	def add(self, libname, distro, deb):
		if libname not in self.libraries:
			self.libraries[libname] = Library(libname)
		self.libraries[libname].add(distro, deb)

def main():
	parser = argparse.ArgumentParser(usage='%(prog)s [options]', description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-v', '--verbose', default=False, help='verbose', action='store_true')
	parser.add_argument('-i', '--scrdir', help='scraper directory')
	parser.add_argument('-o', '--output', help='output directory')
	parser.add_argument('-a', '--arch', default='all', help='architecture name')
	parser.add_argument('-f', '--filter', help='filter deb name')
	parser.add_argument('-s', '--rz-sign', default='rz-sign', help='rz-sign binary path')
	parser.add_argument('-l', '--library', default='libc.a', help='library name to find')
	args = parser.parse_args()

	if len(sys.argv) == 1 or \
		len(args.scrdir) < 1 or \
		len(args.output) < 1 or \
		len(args.arch) < 1 or \
		len(args.rz_sign) < 1 or \
		len(args.library) < 1 or \
		len(args.filter) < 1:
		parser.print_help(sys.stderr)
		sys.exit(1)

	global IS_VERB, SRC_LIB, RZ_SIGN, DEBTOTAL
	IS_VERB = args.verbose
	SRC_LIB = args.library
	RZ_SIGN = args.rz_sign

	archs = {}
	scr_dir = os.path.abspath(args.scrdir)
	os.chdir(args.output)
	db_dir = os.getcwd()

	print("input dir:", scr_dir)
	print("output dir:", db_dir)

	output = system("find '{}' -name '{}' -type f".format(scr_dir, "*.deb")).split("\n")
	n_debs = 0
	for deb in output:
		if args.filter not in deb:
			continue

		if args.verbose:
			print("using", deb)

		distro, name, arch, libname, _ = deb.replace(scr_dir + os.path.sep, "").split(os.path.sep, 4)
		if arch != args.arch and args.arch != "all":
			continue
		if arch not in archs:
			archs[arch] = Arch(arch)
		archs[arch].add(libname, distro + "-" + name, Deb(deb))
		n_debs += 1

	DEBTOTAL = n_debs
	print("found {} deb".format(DEBTOTAL))
	exec_once = False
	for a in archs:
		if a != args.arch and args.arch != "all":
			continue
		exec_once = True
		archs[a].create(db_dir)

	if not exec_once:
		print("something has failed..")

if __name__ == '__main__':
	main()
