#!/usr/bin/env python
#
# Yocto Security Advisory Tracking Utility
# Used to import the output of "bitbake -s" into cvechecker as a
# watchlist.

def normalize_packagename(name):
	"""
	Accepts the name of a Yocto package and returns a modified name
	known to be used in CVE reports
	"""
	package_map = {
		"cdrtools-native": "cdrtools",
		"libpcre" : "pcre",
		"libsndfile1" : "libsndfile",
	}
	if name in package_map:
		name = package_map[name]

	return name

def useless_packagename(name):
	"""
	Checks if the package name is too broad to meaningfully search
	for, or is known to not correspond to an upstream package (e.g,
	core images and tasks). Returns true if those "useless" package
	names are found, and False otherwise.
	"""
	useless_packages = [ "adt-installer", "file", "patch", "time" ]
	if name in useless_packages:
		#print "Skipping package named ", name
		return True

	# -native/-nativesdk:
	if re.search("-native", name):
		#print "Skipping package named ", name
		return True

	# -cross/-cross-sdk:
	if re.search("-cross", name):
		#print "Skipping package named ", name
		return True

	# task-*
	if re.search("^task-", name):
		#print "Skipping package named ", name
		return True

	# core-image-*
	if re.search("^core-image-", name):
		#print "Skipping package named ", name
		return True

	# poky-image-*
	if re.search("^poky-image-", name):
		#print "Skipping package named ", name
		return True

	# -toolchain
	if re.search("-toolchain", name):
		#print "Skipping package named ", name
		return True

	# kernels
	if re.search("^linux-", name):
		#print "Skipping package named ", name
		return True

	return False

def process_bitbake_s(filename):
	"""
	Parses the output of bitbake -s, ignoring the "Parsing" header
	lines, and returns a dictionary of package names and version
	numbers.
	"""
	f = open(filename)
	packages = {}

	#print "Processing package list", filename

	for line in f:
		# Skip the "Parsing" and header lines
		if line.startswith("Load") or  line.startswith("NOTE: ") or line.startswith("Parsing ") or line.startswith("done.") or line.startswith("Package Name") or line.startswith("==") or len(line) == 1:
			continue

		# Extract the package name. Example line:
		# apmd				0:3.2.2-14-r1
		split = line.split(" ", 1)
		# first field is the package name
		packagename = normalize_packagename(split[0])
		if useless_packagename(packagename):
			continue
		rest = split[1].strip()

		# Extract the Poky version number
		split = rest.split(" ", 1)
		if len(split) == 2:
			poky_version = split[1].strip()
		else:
			poky_version = split[0]

		# Strip the package epoch and PR so we're left with the
		# upstream version number
		version = poky_version.split(':', 1)[1]
		version = version.rsplit('-r', 1)[0]

		# Strip out cvs/svn/git commit IDs
		version = re.split('\+cvs', version)[0]
		version = re.split('\+svn', version)[0]
		version = re.split('\+git', version)[0]
		version = re.split('-git', version)[0]

		packages[packagename] = version

	return packages

def handle_options(args):
	import optparse
	parser = optparse.OptionParser(version = "Yocto Security Advisory Scanning Utility",
                                   usage = "%prog [options]")
	parser.add_option("-p", help = "Output from bitbake -s",
                      action = "store", type = "string",
                      dest = "packages_file")
	parser.add_option("-d", help = "Database filename for saving state",
                      action = "store", type = "string",
                      dest = "db_filename")

	options, args = parser.parse_args(args)

	# TODO: Required arguments shouldn't really be processed by optparse
	if options.packages_file is None:
		print "Error: missing required argument -p"
		exit(1)

	if options.db_filename is None:
		print "Error: missing required argument -d"
		exit(1)

	return options

# Main
import os, sys, re, datetime, tempfile, subprocess
from pysqlite2 import dbapi2 as sqlite

opts = handle_options(sys.argv)

packages = process_bitbake_s(opts.packages_file)

# Write the package list in CPE format to a temp file, then
# import the temp file into cvechecker as a "watchlist":
t1 = tempfile.NamedTemporaryFile(delete=False)
for pkg, ver in sorted( packages.items() ):
	t1.write( "cpe:/a:%s:%s:%s:::\n" % (pkg, pkg, ver) )
t1.close()
os.system( "cvechecker -w %s > /dev/null" % (t1.name) )
os.unlink(t1.name)

newdb = True
if os.path.isfile(opts.db_filename):
	print "Note: %s already exists - going to add new entries to this database" % (opts.db_filename)
	newdb = False

dbconn = sqlite.connect(opts.db_filename)
db = dbconn.cursor()

if newdb:
	print "Creating advisories table"
	db.execute('CREATE TABLE advisories (id INTEGER PRIMARY KEY, package TEXT, cve TEXT, cveurl TEXT, status TEXT, last_modified_at DATETIME)')
	dbconn.commit()

# Run a cvechecker vulnerability report and extract the
# package name and CVE ID
t2 = tempfile.NamedTemporaryFile(delete=False)
# tail -n +2 strips the first line of output (a csv header)
os.system( "cvechecker -rYC | tail -n +2 | sort -u > %s" % (t2.name) )

for line in t2:
	pkg = line.split(':')[3]
	cve = line.split(',')[3]

	cveurl = "http://web.nvd.nist.gov/view/vuln/detail?vulnId=%s" % (cve)

	# Skip if this would be a duplicate entry
	db.execute( 'SELECT COUNT(*) FROM advisories WHERE package=? AND cve=?', (pkg, cve) )
	res = db.fetchone()[0]

	if res is 0:
		print "Adding new entry %s for %s" % (cve, pkg)
		now = datetime.datetime.now()
		db.execute( 'INSERT INTO advisories (id, package, cve, cveurl, status, last_modified_at) VALUES(NULL, ?, ?, ?, "NEW", ?)', (pkg, cve, cveurl, now) )
	else:
		print "Skipping duplicate %s for %s" % (cve, pkg)

dbconn.commit()
db.close()
