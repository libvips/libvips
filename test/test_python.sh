#!/bin/sh

# set -x

. ./variables.sh

export GI_TYPELIB_PATH=../libvips 

vipslibs=../libvips/.libs

# we want to test against the built but uninstalled libraries, so we must set
# LD_LIBRARY_PATH or equivalent
case `uname` in
HPUX)
	export SHLIB_PATH=$vipslibs
	;;

Darwin)
	export DYLD_LIBRARY_PATH=$vipslibs
	;;

*)
	export LD_LIBRARY_PATH=$vipslibs
	;;
esac

$PYTHON -m unittest -v test_all 

echo rerunning with VIPS_STALL enabled ...
export VIPS_STALL=1
$PYTHON -m unittest -v test_all 
