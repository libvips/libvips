
EXTRA_DIST = \
	images \
	variables.sh.in \
	test_cli.sh \
	test_formats.sh \
	test_seq.sh \
	test_thumbnail.sh \
	test_threading.sh \
	test_python.sh
	test_arithmetic.py \
	test_colour.py \
	test_create.py \
	test_draw.py \
	test_convolution.py \
	test_conversion.py 

# don't run test_thumbnail.sh by default, it takes ages

# test with python2 and python3 ... we are supposed to work with either

TESTS = \
	test_cli.sh \
	test_formats.sh \
	test_seq.sh \
	test_threading.sh 

clean-local: 
	-rm -rf tmp-*
	-rm -f *.pyc

