#!/bin/sh

#########################################################################
## Weird script to resolve dependencies in FreeBSD 13			#
##									#
## Disclaimer:								#
## This script is specifically designed for my computer system		#
## and may not function properly on any other computer configurations.	#
#########################################################################

#    Copyright (C) 2023  Cistronix
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Set to a list of all the packages that you want to build
synthlist=/root/synthlist

function_print_usage()
{
	printf "\
Usage:
depends.sh command [args]

Available commands:
  depends	Print a list of all ports a port depends on
		args: [portname]
  dependson	Print a list of all ports that depend on [argument]
		args: [string identifying port]
"
	exit
}

function_init_dependslist_database()
{
	mkdir -p ~/.dependsdb
	dbname=$(sha512 -q /usr/ports/INDEX-13)
	optionschecksum=$(find /var/db/ports/ -type f | sort | xargs -n 1 -I % cat % | sha512 -q)
	if [ -e ~/.dependsdb/$dbname ] && [ -e ~/.dependsdb/$optionschecksum ]; then
		database=~/.dependsdb
	else
		database=~/.dependsdb
		rm -Rf $database
		mkdir -p $database
		cd $database
		mkdir -p accessibility arabic archivers astro audio base benchmarks biology cad chinese comms converters databases deskutils devel dns editors emulators finance french ftp games german graphics hebrew hungarian irc japanese java korean lang mail math misc multimedia net net-im net-mgmt net-p2p news polish ports-mgmt portuguese print russian science security shells sysutils textproc ukrainian vietnamese www x11 x11-clocks x11-drivers x11-fm x11-fonts x11-servers x11-themes x11-toolkits x11-wm
		cd
		touch $database/$dbname
		touch $database/$optionschecksum
	fi
	if [ "$1" = "fullinit" ] && [ ! -e $database/fullinitdone ]; then
		tempdir=$(mktemp -d)
		cat $synthlist | awk -F "@" '{print $1}' > $tempdir/level1a
		level=1
		maxlevel=1000
		while test $level -lt $maxlevel; do
			printf "\rLevel %003d / $(($maxlevel - 1))" "$level" 1>&2
			touch $tempdir/level${level}a
			cat $tempdir/level${level}a | sort -u > $tempdir/level${level}
			while read line <&6; do
				test -e $database/$line || make -C /usr/ports/$line run-depends-list build-depends-list | grep "/usr/ports/" | sed 's/\/usr\/ports\///' >> $database/$line
				test -e $database/$line && cat $database/$line >> $tempdir/level$(($level + 1))a
			done 6< $tempdir/level${level}
			level=$(($level + 1))
		done
		touch $database/fullinitdone
		printf "\n"
	fi
}

function_dependslist_database()
{
	function_init_dependslist_database
	tempdir=$(mktemp -d)
	fulllist=$(mktemp)
	condenselist=$(mktemp)

	test -e $database/$1 || make -C /usr/ports/$1 run-depends-list build-depends-list | grep "/usr/ports/" | sed 's/\/usr\/ports\///' >> $database/$1
	test -e $database/$1 && cat $database/$1 >> $tempdir/level1a

	level=1
	maxlevel=1000
	while test $level -lt $maxlevel; do
		printf "\rLevel %003d / $(($maxlevel - 1))" "$level" 1>&2
		touch $tempdir/level${level}a
		cat $tempdir/level${level}a | sort -u > $tempdir/level${level}
		while read line <&6; do
			test -e $database/$line || make -C /usr/ports/$line run-depends-list build-depends-list | grep "/usr/ports/" | sed 's/\/usr\/ports\///' >> $database/$line
			test -e $database/$line && cat $database/$line >> $tempdir/level$(($level + 1))a
		done 6< $tempdir/level${level}
		level=$(($level + 1))
	done

	level=$(($level - 1))
	unresolved=$(cat $tempdir/level$(($level - 10)) | wc -l | awk '{print $1}')
	test $unresolved -gt 0 && echo "" && echo "The following dependencies are unresolved:" && cat $tempdir/level$(($level - 10))

	while test $level -gt 0; do
		printf "\rLevel %003d / $(($maxlevel - 1))" "$level" 1>&2
		cat $tempdir/level$level >> $fulllist
		level=$(($level - 1))
	done

	totallinecount=$(($(cat $fulllist | wc -l | awk '{print $1}')))
	currentlinecount=0
	while read line <&6; do
		currentlinecount=$(($currentlinecount + 1))
		percent=$(bc -e "scale=2;($currentlinecount * 100.00) / $totallinecount")
		printf "\r%.2f%% completed..." "${percent}" 1>&2
		grep -q "^$line$" $condenselist || echo $line >> $condenselist
	done 6< $fulllist
	echo $1 >> $condenselist
	printf "\r                            \r" 1>&2
	rm -R -f $tempdir
}

if [ "$1" = "depends" ]; then
	test $2 && test -d /usr/ports/$2 && function_dependslist_database $2 && cat $condenselist && exit
	function_print_usage
fi

if [ "$1" = "dependson" ]; then
	test $2 || function_print_usage
	function_init_dependslist_database fullinit
	cd ~/.dependsdb
	find . -type f | sed 's/^.\///' | xargs -n 1 -I % grep -H "$2" % | awk -F ":" '{print $1" depends on "$2}' | sort -u
	exit

fi

function_print_usage
