Yocto Security Advisory Tracking Utility Instructions

== Introduction ==

The Yocto Security Advisory Tracking Utility is a tool used by the Yocto Project to track security advisories against our recipes.

The support scripts were written by Scott Garman <scott.a.garman@intel.com>. They are trivial wrappers to keep track of the output from cvechecker, a tool written by Sven Vermeulen <sven.vermeulen@siphos.be>.

Many thanks to Sven for his great work on cvechecker!

These scripts are distributed under the GPLv2. See the COPYING file for the text of the GPLv2 license.

== Setup ==

This tool depends on cvechecker v3.1

http://cvechecker.sourceforge.net/

Please read the cvechecker user guide for context on the utility:

http://cvechecker.sourceforge.net/docs/userguide.html

We will be using cvechecker with "watchlists" so we can import our package list from the Yocto Project and not scan the local filesystem for package versions. 

You'll need the following packages installed on your host: autoconf, automake, m4, libxslt, libconfig, sqlite3, wget.

Create a separate user account for running this tool - this example uses a user and group named "cvechecker" - this user should have umask set to 007. 

Download version 3.1 of cvechecker and extract the tarball.

Apply the "cvechecker_yocto_changes_v3.1.patch" patch to the sources and build cvechecker: 

	cd cvechecker-3.1
	patch -p1 < ../cvechecker_yocto_changes_v3.1.patch
	./configure --enable-sqlite3
	make
	sudo make install
	sudo make postinstall

All of the commands beyond this point are to be run as the user cvechecker. 

Initialize the cvechecker sqlite3 databases in /usr/local/var/cvechecker with:

	cvechecker -i

You only have to run this once after installing cvechecker.

== Use ==

Run "pullcves pull" to download the National Vulnerability Database XML files and import them into your databases. This will take a while the first time. Future runs of this command will only download new advisories since the last download.

What I do is have the cvechecker user have a copy of the Poky git repository. Using the branch you want to check, run "bitbake -s" to generate the list of all packages. Redirect STDOUT to a file, e.g. "bitbake -s > bitbake_s_bernard_2011-04-11.txt".

Now you can use this package list as an argument to the scan_yocto_packagelist.py script:

	scan_yocto_packagelist.py -p bitbake_s_bernard_2011-04-11.txt -d bernard.db

The -d option allows you to specify the name of the sqlite3 database which keeps track of the state of potentially relevant security advisories. In this database, the state field can be one of:

* NEW: The security advisory has not yet been reviewed by the administrator to ascertain its relevance
* INVALID: The security advisory has been reviewed and deemed to be irrelevant
* INPROG: The security advisory has been reviewed and the recipe maintainer notified that an upgrade or fix is needed
* FIXED: The security advisory has been reviewed, and the recipe has been updated or fixed in the git tree

== Final Thoughts ==

This utility is just screaming for a web-based interface. If you'd like to volunteer to develop such a web based front-end, please contact Scott Garman <scott.a.garman@intel.com>.
