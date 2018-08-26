#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) 2008 Yahoo!, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the author nor the names of any co-contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$

CRASHDIR_DEFAULT="/var/crash"
GDB_DEFAULT="/usr/local/bin/gdb"
GDB_PATHS="${GDB_DEFAULT} /usr/libexec/gdb /usr/bin/gdb"

CRASHDIR=""
GDB=""
INFO=""
KERNEL=""
VMCORE=""

die()
{
	echo "$@" >&2
	exit 1
}

# Remove an uncompressed copy of a dump.
cleanup()
{
	if [ -e "${VMCORE}" ]; then
		rm -f "${VMCORE}"
	fi
}

usage()
{
	die "usage: crashinfo [-b] [-d crashdir] [-n dumpnr] [-k kernel] [core]"
}

last_dumpnr()
{
	local next

	if [ ! -r "${CRASHDIR}/bounds" ]; then
		return 1
	fi

	next=$(cat "${CRASHDIR}/bounds")
	if [ -z "${next}" ] || [ "${next}" -eq 0 ]; then
		return 1
	fi

	echo $((next - 1))
}

# Find a gdb binary to use and save the value in GDB.
gdb_find()
{
	local binary path

	path=""

	for binary in ${GDB_PATHS}; do
		if [ -x "${binary}" ]; then
			path="${binary}"
			break
		fi
	done

	echo "${path}"
}

# Run a single gdb command against a kernel file in batch mode.
# The kernel file is specified as the first argument and the command
# is given in the remaining arguments.
gdb_command()
{

	if [ "${GDB}" = "${GDB_DEFAULT}" ]; then
		"${GDB}" -batch -ex "$@" "${KERNEL}"
	else
		echo -e "$@" | "${GDB}" -batch -x /dev/stdin "${KERNEL}"
	fi
}

kernel_find()
{
	local iversion kernel kversion path

	path=""

	iversion=$(awk '
	/Version String/ {
		print
		nextline=1
		next
	}
	nextline==1 {
		if ($0 ~ "^  [A-Za-z ]+: ") {
			nextline=0
		} else {
			print
		}
	}' "${INFO}")

	# Look for a matching kernel version, handling possible truncation
	# of the version string recovered from the dump.
	for kernel in $(sysctl -n kern.bootfile) $(ls -t /boot/*/kernel); do
		kversion=$(gdb_command 'printf "  Version String: %s", version' |
		    awk "{line=line\$0\"\n\"} END{print substr(line,1,${#iversion})}" \
		    2>/dev/null)
		if [ "${iversion}" = "${kversion}" ]; then
			path="${kernel}"
			break
		fi
	done

	echo "${path}"
}

core_crashdir()
{
	local crashdir path

	path="${1}"

	crashdir=$(dirname "${path}")
	echo "${crashdir}"
}

core_dumpnr()
{
	local dumpnr path

	path="${1}"

	dumpnr=$(expr $(basename "${path}") : 'vmcore\.\([0-9]*\)')
	echo "${dumpnr}"
}

core_command()
{
	local cmd kernel title vmcore

	if [ $# -eq 1 ]; then
		title="${1}"

		cmd="${title} -M ${VMCORE} -N ${KERNEL}"
	else
		title="${1}"
		cmd="${2}"

		# Parse a command format string and replace:
		# - %% with %;
		# - %c with a vmcore path;
		# - %k with a kernel path.

		# Characters '&', '/' and '\' in vmcore and kernel paths must be
		# first escaped for sed(1).
		vmcore=$(echo "${VMCORE}" | sed -E 's/([&\/\\])/\\\1/g')
		kernel=$(echo "${KERNEL}" | sed -E 's/([&\/\\])/\\\1/g')

		cmd=$(echo "${cmd}" | sed -E "s/((^|[^%])(%%)*)%c/\1${vmcore}/g;\
		    s/((^|[^%])(%%)*)%k/\1${kernel}/g; s/%%/%/g")
	fi

	cat << EOF

------------------------------------------------------------------------
${title}

$(${cmd})
EOF
}

core_kgdb()
{
	local cmd file

	cmd="${1}"

	# XXX: /bin/sh on 7.0+ is broken so we can't simply pipe the commands to
	# kgdb via stdin and have to use a temporary file instead.
	file=$(mktemp /tmp/crashinfo.XXXXXX)
	if [ $? -eq 0 ]; then
		cat << EOF >"${file}"
$(echo "${cmd}" | sed -E $'s/;/\\\n/g')
quit
EOF
		"${GDB%gdb}kgdb" "${KERNEL}" "${VMCORE}" <"${file}"
		echo
		rm -f "${file}"
	fi
}

core_generate()
{
	local core hostname machine osrelease ostype version

	core="${1}"

	umask 077

	if [ -n "${core}" ]; then
		echo "Writing crash summary to ${core}."
		exec >"${core}" 2>&1
	fi

	# Simulate uname.
	ostype=$(gdb_command 'printf "%s", ostype')
	osrelease=$(gdb_command 'printf "%s", osrelease')
	version=$(gdb_command 'printf "%s", version' | tr '\t\n' '  ')
	machine=$(gdb_command 'printf "%s", machine')

	hostname=$(hostname)
	cat << EOF
${hostname} dumped core - see ${VMCORE}

$(date)

${ostype} ${hostname} ${osrelease} ${version} ${machine}

$(sed -ne '/^  Panic String: /{s//panic: /;p;}' "${INFO}")

EOF

	core_kgdb "bt"
	core_command "ps -axlww"
	core_command "vmstat -s"
	core_command "vmstat -m"
	core_command "vmstat -z"
	core_command "vmstat -i"
	core_command "pstat -T"
	core_command "pstat -s"
	core_command "iostat"
	core_command "ipcs -a" "ipcs -C %c -N %k -a"
	core_command "ipcs -T" "ipcs -C %c -N %k -T"
	# XXX: This doesn't actually work in 5.x+.
	if false; then
		core_command "w -dn"
	fi
	core_command "nfsstat"
	core_command "netstat -s"
	core_command "netstat -m"
	core_command "netstat -anA"
	core_command "netstat -aL"
	core_command "fstat"
	core_command "dmesg -a"
	core_command "kernel config" "config -x %k"
	core_command "ddb capture buffer" "ddb capture -M %c -N %k print"
}

main()
{
	local batch crashdir dumpnr opt vmcore

	batch=false
	crashdir=""
	dumpnr=""

	while getopts "bd:k:n:" opt; do
		case "${opt}" in
		b)
			batch=true
			;;
		d)
			crashdir="${OPTARG}"
			[ -n "${crashdir}" ] || usage
			;;
		k)
			KERNEL="${OPTARG}"
			[ -n "${KERNEL}" ] || usage
			;;
		n)
			dumpnr="${OPTARG}"
			[ -n "${dumpnr}" ] || usage
			;;
		*)
			usage
			;;
		esac
	done
	shift $((OPTIND - 1))

	if [ $# -eq 1 ]; then
		if [ -n "${crashdir}" ]; then
			die "Flag -d and an explicit vmcore are mutually exclusive."
		elif [ -n "${dumpnr}" ]; then
			die "Flag -n and an explicit vmcore are mutually exclusive."
		fi
	elif [ $# -gt 1 ]; then
		usage
	fi

	vmcore="${1}"

	if [ $# -eq 1 ]; then
		# Figure out a crash directory from the vmcore name.
		CRASHDIR=$(core_crashdir "${vmcore}")
	elif [ -n "${crashdir}" ]; then
		CRASHDIR="${crashdir}"
	else
		CRASHDIR="${CRASHDIR_DEFAULT}"
	fi

	if [ $# -eq 1 ]; then
		# Figure out a dump number from the vmcore name.
		dumpnr=$(core_dumpnr "${vmcore}")
		if [ -z "${dumpnr}" ]; then
			die "Unable to determine dump number from vmcore file ${vmcore}."
		fi
	elif [ -z "${dumpnr}" ]; then
		# If we don't have an explicit dump number, operate on the most
		# recent dump.
		dumpnr=$(last_dumpnr)
		if [ -z "${dumpnr}" ]; then
			die "No crash dumps in ${crashdir}."
		fi
	fi

	INFO="${CRASHDIR}/info.${dumpnr}"
	VMCORE="${CRASHDIR}/vmcore.${dumpnr}"

	GDB=$(gdb_find)
	if [ -z "${GDB}" ]; then
		die "Unable to find a kernel debugger."
	fi

	if [ -z "${KERNEL}" ]; then
		# If the user didn't specify a kernel, then try to find one.
		KERNEL=$(kernel_find)
		if [ -z "${KERNEL}" ]; then
			die "Unable to find a matching kernel for ${VMCORE}."
		fi
	elif [ ! -e "${KERNEL}" ]; then
		die "Unable to find a kernel ${KERNEL}."
	fi

	if [ ! -e "${INFO}" ]; then
		die "Unable to find an info file ${INFO}."
	fi

	if [ ! -e "${VMCORE}" ]; then
		if [ -e "${VMCORE}.gz" ]; then
			trap cleanup EXIT HUP INT QUIT TERM
			gzcat "${VMCORE}.gz" >"${VMCORE}"
		elif [ -e "${VMCORE}.zst" ]; then
			trap cleanup EXIT HUP INT QUIT TERM
			zstdcat "${VMCORE}.zst" >"${VMCORE}"
		else
			die "Unable to find a core dump ${VMCORE}."
		fi
	fi

	if "${batch}"; then
		core_generate "${CRASHDIR}/core.txt.${dumpnr}"
	else
		core_generate
	fi
}

main "$@"
