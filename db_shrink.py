# SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import sys
import os
from difflib import SequenceMatcher

DESCRIPTION='Rizin (source) signature database shrinker'
EPILOG=''

def listdirs(path):
	return [name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))]

def listfiles(path):
	return [name for name in os.listdir(path) if os.path.isfile(os.path.join(path, name))]

def is_bad_symbol(name):
	if name.startswith('case.0x'):
		return True
	return False

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def similarity_group(grp):
	avg = 0
	cnt = 0
	for k in grp:
		for m in grp:
			if k == m:
				continue
			avg += similarity(k, m)
			cnt += 1
	if cnt < 1:
		# means the names in grp are the same.
		return 1.0
	return avg / cnt


class PacFile(object):
	def __init__(self, arch, bits, system, library, verbose):
		super(PacFile, self).__init__()
		self.outname = "{}_{}_{}_{}.pac".format(arch, bits, system, library)
		self.verbose = verbose
		self.signatures = {}

	def generate(self, outdir):
		outfile = os.path.join(outdir, self.outname)
		with open(outfile, "w") as fp:
			for crc in self.signatures:
				for pre in self.signatures[crc]:
					fp.write(self.signatures[crc][pre] + "\n")
			fp.write("---\n")
		print("{} has been created".format(outfile))

	def parse(self, filepath):
		if not filepath.endswith(".pac"):
			if self.verbose:
				print("not a pac file: {}".format(filepath))
			return

		if self.verbose:
			print("parsing {}".format(filepath))
		with open(filepath) as fp:
			for line in fp:
				line = line.rstrip()
				if line == "---":
					break
				tokens = line.split(" ")

				if is_bad_symbol(tokens[5]):
					continue

				if tokens[3] == "0000":
					# drop any signature with function size of zero
					continue

				key = " ".join(tokens[1:3])
				prelude = tokens[0]

				if not key in self.signatures:
					self.signatures[key] = {}
					self.signatures[key][prelude] = set()
				elif not prelude in self.signatures[key]:
					self.signatures[key][prelude] = set()

				self.signatures[key][prelude].add(" ".join(tokens[0:6]))

	def resolve_conflicts(self, threshold):
		n_bad_conflicts = 0
		n_resolved = 0
		n_total = 0
		for crc in self.signatures:
			to_drop = []
			for prelude in self.signatures[crc]:
				self.signatures[crc][prelude] = list(self.signatures[crc][prelude])
				self.signatures[crc][prelude].sort()
				n_sigs = len(self.signatures[crc][prelude])
				n_total += n_sigs
				if n_sigs < 2:
					self.signatures[crc][prelude] = self.signatures[crc][prelude][0]
					continue
				to_drop.append(prelude)

			for prelude in to_drop:
				n_sigs = len(self.signatures[crc][prelude])
				fcns = [s.split(" ")[-1] for s in self.signatures[crc][prelude]]
				if crc == "00 0000":
					# too small functions gets always dropped
					if self.verbose:
						print("[{}] dropping {} signatures with prelude {} ({})".format(crc, n_sigs, prelude, ', '.join(fcns)))
					del self.signatures[crc][prelude]
					n_bad_conflicts += n_sigs
					continue

				simgrp = similarity_group(fcns)
				if simgrp < threshold:
					if self.verbose:
						print("[{}] dropping {} signatures with prelude {} ({}) due similarity of {:.2f}".format(crc, n_sigs, prelude, ', '.join(fcns), simgrp))
					del self.signatures[crc][prelude]
					n_bad_conflicts += n_sigs
					continue

				n_resolved += n_sigs
				self.signatures[crc][prelude] = self.signatures[crc][prelude][0]
				if self.verbose:
					print("[{}] keeping {} signatures with prelude {} ({}) and similarity of {}".format(crc, n_sigs, prelude, ', '.join(fcns), simgrp))

		if n_total < 1:
			print("the script could not find and load any pac file")
			sys.exit(0)

		print("dropped {} signatures due conflicts and resolved {} over {} total.".format(n_bad_conflicts, n_resolved, n_total))


def main():
	parser = argparse.ArgumentParser(usage='%(prog)s [options]', description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-v', '--verbose', default=False, help='verbose', action='store_true')
	parser.add_argument('-i', '--input', default='', help='input directory with multiple folders containing same lib but different versions')
	parser.add_argument('-o', '--output', default='', help='output directory where to generate the final pac file')
	parser.add_argument('-a', '--arch', default='', help='Rizin architecture name (must follow rizin names)')
	parser.add_argument('-V', '--variant', default='', help='variant name (can be empty)')
	parser.add_argument('-b', '--bits', default='', help='Architecture bits (use `all` for accepting all the bits)')
	parser.add_argument('-s', '--system', default='', help='System/OS name (linux, mac, win, haiku)')
	parser.add_argument('-l', '--library', default='', help='library name (example: libc.a)')
	parser.add_argument('-t', '--threshold', default=0.66, type=float, help='threshold for similarity (default 0.66)')
	args = parser.parse_args()

	if len(sys.argv) == 1 or \
		len(args.input) == 0 or \
		len(args.output) == 0 or \
		len(args.arch) == 0 or \
		len(args.bits) == 0  or \
		len(args.system) == 0 or \
		len(args.library) == 0:
		parser.print_help(sys.stderr)
		sys.exit(1)

	system = args.system
	if len(args.variant) > 0:
		system += "_" + args.variant

	pac = PacFile(args.arch, args.bits, system, args.library, args.verbose)

	dirs = listdirs(args.input)
	for d in dirs:
		d = os.path.join(args.input, d)
		if args.verbose:
			print("listing files in {}".format(d))
		files = listfiles(d)
		for file in files:
			filepath = os.path.join(d, file)
			pac.parse(filepath)

	pac.resolve_conflicts(args.threshold)
	pac.generate(args.output)

if __name__ == '__main__':
	main()
