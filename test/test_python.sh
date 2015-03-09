#!/bin/sh

# set -x

# don't run this set of tests as part of make check -- some platforms do make
# check before install and it's too hard to make pyvips8 work without
# installation

. ./variables.sh

echo "testing with python2 ..."

python2 test_all.py 

echo "testing with python3 ..."

python3 test_all.py 
