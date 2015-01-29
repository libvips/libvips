#!/bin/sh

# set -x

# don't run this set of tests as part of make check -- some platforms do make
# check before install and it's too hard to make pyvips8 work without
# installation

. ./variables.sh

echo "testing with python2 ..."

python2 test_arithmetic.py 
python2 test_colour.py 
python2 test_conversion.py 
python2 test_convolution.py 
python2 test_create.py
python2 test_draw.py
python2 test_histogram.py
python2 test_morphology.py
python2 test_resample.py

echo "testing with python3 ..."

python3 test_colour.py 
python3 test_arithmetic.py 
python3 test_conversion.py
python3 test_convolution.py 
python3 test_create.py
python3 test_draw.py
python3 test_histogram.py
python3 test_morphology.py
python3 test_resample.py
