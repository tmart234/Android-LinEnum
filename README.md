This is a forked version that supports Android


# LinEnum
For more information visit www.rebootuser.com

Note: Export functionality is currently in the experimental stage.

General usage:

you may have to format this file to run on Android device (it can have errors with last if statement):
* tr -d '\r' < LinEnum.sh > LinEnum_fixed.sh
* chmod 755 LinEnum_fixed.sh
* sh LinEnum_fixed.sh


version 0.99

* Example: ./LinEnum.sh -s -k keyword -r report -e /tmp/ -t 

OPTIONS:
* -k	Enter keyword
* -e	Enter export location
* -t	Include thorough (lengthy) tests
* -s	Supply current user password to check sudo perms (INSECURE)
* -r	Enter report name
* -h	Displays this help text


Running with no options = limited scans/no output file

* -e Requires the user enters an output location i.e. /tmp/export. If this location does not exist, it will be created.
* -r Requires the user to enter a report name. The report (.txt file) will be saved to the current working directory.
* -t Performs thorough (slow) tests. Without this switch default 'quick' scans are performed.
* -s Use the current user with supplied password to check for sudo permissions - note this is insecure and only really for CTF use!
* -k An optional switch for which the user can search for a single keyword within many files (documented below).

See CHANGELOG.md for further details


