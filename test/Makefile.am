
EXTRA_DIST = \
	images \
	variables.sh.in \
	test_cli.sh \
	test_formats.sh \
	test_seq.sh \
	test_thumbnail.sh \
	test_threading.sh \
	test_python.sh
	test_all.py \
	test_arithmetic.py \
	test_colour.py \
	test_conversion.py \
	test_convolution.py \
	test_create.py \
	test_draw.py \
	test_histogram.py \
	test_morphology.py \
	test_resample.py 

# don't run test_thumbnail.sh by default, it takes ages

TESTS = \
	test_cli.sh \
	test_formats.sh \
	test_seq.sh \
	test_threading.sh 

clean-local: 
	-rm -rf tmp-*
	-rm -f *.pyc

