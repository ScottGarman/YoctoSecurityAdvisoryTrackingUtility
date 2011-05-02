#!/usr/bin/env python
#
# Perform a query on an advisory database and print the results
# in a human-friendly format.

import os, sys, string
from pysqlite2 import dbapi2 as sqlite

if len(sys.argv)!= 3:
	print "Usage: %s <statedb filename> <command>" % (sys.argv[0])
	print "Where command is [all|new|inprog|fixed|invalid]"
	exit(1)

db_filename = sys.argv[1]
cmd = sys.argv[2].upper()

if not os.path.isfile(db_filename):
	print "Error: %s does not exist" % (db_filename)
	exit(1)

dbconn = sqlite.connect(db_filename)
db = dbconn.cursor()

if cmd == "ALL":
	print "Displaying all entries"
	db.execute('SELECT package, cve, cveurl, status FROM advisories')
	for row in db:
		print "%15s %s %s %s" % row
else:
	status = (cmd,)
	db.execute( 'SELECT package, cve, cveurl FROM advisories WHERE status=?', status )
	for row in db:
		print "%15s %s %s" % row

db.close()
