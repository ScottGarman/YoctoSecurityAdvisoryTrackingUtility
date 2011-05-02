#!/usr/bin/env python
#
# Update the status of a security advisory

import os, sys, string
from pysqlite2 import dbapi2 as sqlite

if len(sys.argv) != 5:
	print "Usage: %s <statedb filename> <command> <package> <cve>"
	print "Where commands are [new|inprog|fixed|invalid]"
	exit(1)

db_filename = sys.argv[1]
cmd = sys.argv[2].upper()
pkg = sys.argv[3]
cve = sys.argv[4]

if not os.path.isfile(db_filename):
	print "Error: %s does not exist" % (db_filename)
	exit(1)

dbconn = sqlite.connect(db_filename)
db = dbconn.cursor()

# Ensure the entry to be changed exists
db.execute( 'SELECT COUNT(*) FROM advisories WHERE package=? AND cve=?', (pkg, cve) )
res = db.fetchone()[0]

if res is 0:
	print "Error: Unable to find package %s with CVE %s in the database" % (pkg, cve)
	exit(1)

if res is not 1:
	print "Error: Multiple results returned for package %s with CVE %s" % (pkg, cve)
	exit(1)

status = cmd
print "UPDATE advisories SET status=\"%s\" WHERE package=\"%s\" AND CVE=\"%s\"" % (status, pkg, cve)
db.execute( 'UPDATE advisories SET status=? WHERE package=? AND CVE=?', (status, pkg, cve) )

dbconn.commit()
db.close()
