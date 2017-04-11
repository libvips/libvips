#!/bin/sh

# set -x

. ./variables.sh

# make a large PNG, roughly the size of Chicago.png
printf "building huge test PNG image ... "
$vips replicate $image $tmp/huge.png 30 5
echo "ok"

huge=$tmp/huge.png

printf "testing vipsthumbnail ... "
rm -f $tmp/x.png
$vipsthumbnail $huge -o $tmp/x.png
if ! $vipsheader $tmp/x.png > /dev/null 2>&1 ; then
	echo "vipsthumbnail failed in basic mode"
	exit 1
fi
echo "ok"

if [ ! -d $tmp/readonly ] ; then
	mkdir $tmp/readonly
	chmod ugo-wx $tmp/readonly
fi 
export TMPDIR=$tmp/readonly

printf "testing vipsthumbnail does not make temps ... "
rm -f $tmp/x.png
$vipsthumbnail $huge -o $tmp/x.png
if ! $vipsheader $tmp/x.png > /dev/null 2>&1 ; then
	echo "vipsthumbnail made a temp"
	exit 1
fi
echo "ok"

printf "testing shrink does not make temps ... "
rm -f $tmp/x.png
$vips shrink $huge $tmp/x.png 230 230 
if ! $vipsheader $tmp/x.png > /dev/null 2>&1 ; then
	echo "shrink made a temp"
	exit 1
fi
echo "ok"

printf "testing reduce does not make temps ... "
rm -f $tmp/x.png
$vips reduce $huge $tmp/x.png 3 3 
if ! $vipsheader $tmp/x.png > /dev/null 2>&1 ; then
	echo "reduce made a temp"
	exit 1
fi
echo "ok"
