#!/bin/sh

# set -x

. ./variables.sh

echo "testing with python2 ..."

python2 test_arithmetic.py 
python2 test_colour.py 
python2 test_conversion.py 
python2 test_convolution.py 

echo "testing with python3 ..."

python3 test_colour.py 
python3 test_arithmetic.py 
python3 test_conversion.py
python3 test_convolution.py 

