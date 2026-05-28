# Android-LinEnum

An Android-focused enumeration script, originally forked from
[rebootuser/LinEnum](https://github.com/rebootuser/LinEnum) and rewritten for
Android / embedded Android (e.g. Android TV, set-top boxes) targets.

It uses Android-native tooling (`getprop`, `pm`, `dumpsys`, `getenforce`) and
checks Android-specific surfaces: ADB/debug state, verified boot & bootloader
lock, partition/DTB layout, SELinux enforcement, installed packages and
permissions, init `.rc` services, app sandboxes, and known Android version
vulnerabilities.

Note: Export functionality is currently in the experimental stage.

## General usage

Push the script to the device and run it under the Android shell. You may have
to strip CRLF line endings first:

```
tr -d '\r' < LinEnum.sh > LinEnum_fixed.sh
chmod 755 LinEnum_fixed.sh
sh LinEnum_fixed.sh
```

version 1.0 (Android)

* Example: `./LinEnum.sh -k keyword -r report -e /sdcard/ -t`

## Options

* `-k`	Enter keyword
* `-e`	Enter export location
* `-t`	Include thorough (lengthy) tests
* `-r`	Enter report name
* `-h`	Displays this help text

Running with no options = limited scans / no output file

* `-e` Requires the user to enter an output location, e.g. `/sdcard/export`. If this location does not exist, it will be created.
* `-r` Requires the user to enter a report name. The report (.txt file) will be saved to the current working directory.
* `-t` Performs thorough (slow) tests. Without this switch a default 'quick' scan is performed.
* `-k` An optional switch with which the user can search for a single keyword within many files.

## Related tools

* `uboot.py` — U-Boot interaction / enumeration helper.
* `extract.sh`, `extract2.sh` — partition/firmware extraction helpers.
* `embedded_notes.txt` — embedded-systems pentesting reference notes.

See CHANGELOG.md for further details


