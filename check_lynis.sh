#!/bin/bash

# Lynis plugin for Nagios
#
# Written by Mark Ruys <mark.ruys@peercode.nl>
# Last Modified: 07-01-2014
#
# Usage: ./check_lynis.sh
#
# Description:
#
# This plugin will scan the Lynis report file.  Lynis is an auditing tool
# which can be downloaded from http://rootkit.nl.
#
# Output:
#
# The last computed hardening index.
#
# Notes:
#
# The report file must be readable by the Nagios user.

PROGNAME=`/usr/bin/basename $0`
PROGPATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
REVISION="1.0.0"

STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE_DEPENDENT=4

# Define default values

reportfile="/var/log/lynis-report.dat"
index_warn=90
index_crit=50
age_warn=2
age_crit=10

# Help info

print_help() {
    cat <<HERE
$PROGNAME $REVISION

This plugin checks the hardening index of the Lynis audit report.

Usage:
 $PROGNAME [-w limit] [-c limit] [-W limit] [-C limit] [-R report]

Options:
 -h, --help
    Print detailed help screen
 -V, --version
    Print version information
 -c, --critical=PERCENT
    Exit with CRITICAL status if index is less than PERCENT, default ${index_crit}
 -w, --warning=PERCENT
    Exit with WARNING status if index is less than PERCENT, default ${index_warn}
 -C, --rcritical=INTEGER
    Exit with CRITICAL status if report is more the INTEGER days old, default ${age_crit}
 -W, --rwarning=INTEGER
    Exit with WARNING status if report is more the INTEGER days old, default ${age_warn}
 -R, --report=STRING
    Define location of report file, default ${reportfile}
HERE
}

# Parse the command line arguments

TEMP=$(getopt -o hVw:c:W:C:R: --long help,version,warning:,critical:,rwarning:,rcritical:,report: -n "${PROGNAME}" -- "$@")

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

# Note the quotes around `$TEMP': they are essential!
eval set -- "${TEMP}"

while true ; do
    case "$1" in
        --help|-h)
            print_help
            exit $STATE_UNKNOWN
            ;;
        --version|-V)
            echo "$PROGNAME $REVISION"
            exit $STATE_UNKNOWN
            ;;
        --warning|-w)
            index_warn=$2
            shift
            ;;
        --rwarning|-W)
            age_warn=$2
            shift
            ;;
        --critical|-c)
            index_crit=$2
            shift
            ;;
        --rcritical|-C)
            age_crit=$2
            shift
            ;;
        --report|-R)
            reportfile=$2
            shift
            ;;
        --) shift ; break ;;
        *)  echo "Internal error!"
            exit $STATE_UNKNOWN
            ;;
    esac
    shift
done

# Sanety checks

if [ ! -r ${reportfile} ]; then
	echo "UNKN Can't open ${reportfile} for reading"
	exit $STATE_UNKNOWN
fi

hardening_index=$(awk 'BEGIN{FS="="} /^hardening_index=/{print $2}' "${reportfile}")
if [ -z "$hardening_index" ]; then
	echo "UNKN Can't find hardening_index"
	exit $STATE_UNKNOWN
fi

report_datetime_start=$(awk 'BEGIN{FS="="} /^report_datetime_start=/{print $2}' "${reportfile}")
if [ -z "$report_datetime_start" ]; then
	echo "UNKN Can't find report_datetime_start"
	exit $STATE_UNKNOWN
fi
age=$(($(date +"%s") - $(date --date="${report_datetime_start}" +"%s")))
if [ $age -le 0 ]; then
	echo "UNKN Can't parse report_datetime_start: ${report_datetime_start}"
	exit $STATE_UNKNOWN
fi

if [ $index_crit -gt $index_warn ]; then
	echo "UNKN warning threshold (${index_warn}) for index should not be smaller than critical threshold (${index_crit})"
	exit $STATE_UNKNOWN
fi
if [ $age_crit -lt $age_warn ]; then
	echo "UNKN warning threshold (${age_warn}) for report age should not be bigger than critical threshold (${age_crit})"
	exit $STATE_UNKNOWN
fi

lynis_update_available=$(awk 'BEGIN{FS="="} /^lynis_update_available=/{print $2}' "${reportfile}")

# Check critical levels

if [ $hardening_index -le $index_crit ]; then
	echo "CRIT Index: $hardening_index"
	exit $STATE_CRITICAL
fi
if [ $age -ge $((${age_crit} * 24 * 60 * 60)) ]; then
	echo "CRIT Report too old: ${report_datetime_start}"
	exit $STATE_CRITICAL
fi

# Check warning levels

if [ $hardening_index -le $index_warn ]; then
	echo "WARN Index: $hardening_index"
	exit $STATE_WARNING
fi
if [ $age -ge $((${age_warn} * 24 * 60 * 60)) ]; then
	echo "WARN Report too old: ${report_datetime_start}"
	exit $STATE_WARNING
fi

if [ $lynis_update_available -ne 0 ]; then
	echo "WARN Lynis update available -- please update"
	exit $STATE_WARNING
fi

# All checks passed

echo "OK Index: ${hardening_index}"
exit $exitstatus

