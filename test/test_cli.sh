#!/bin/sh

# this test is also in test_resample.py (though much smaller and neater) ...
# keep this test to exercise the cli interface

# set -x

. ./variables.sh

# is a difference beyond a threshold? return 0 (meaning all ok) or 1 (meaning
# error, or outside threshold)
# 
# use bc since bash does not support fp math
break_threshold() {
	diff=$1
	threshold=$2
	return $(echo "$diff <= $threshold" | bc -l)
}

# subtract, look for max difference less than a threshold
test_difference() {
	before=$1
	after=$2
	threshold=$3

	$vips subtract $before $after $tmp/difference.v
	$vips abs $tmp/difference.v $tmp/abs.v 
	dif=$($vips max $tmp/abs.v)

	if break_threshold $dif $threshold; then
		echo "difference is $dif"
		exit 1
	fi
}

test_rotate() {
	im=$1
	inter=$2

	printf "testing $inter ... "

	# 90 degree clockwise rotate 
	trn="0 1 1 0"

	$vips affine $im $tmp/t1.v "$trn" --interpolate $inter
	$vips affine $tmp/t1.v $tmp/t2.v "$trn" --interpolate $inter
	$vips affine $tmp/t2.v $tmp/t1.v "$trn" --interpolate $inter
	$vips affine $tmp/t1.v $tmp/t2.v "$trn" --interpolate $inter

	test_difference $im $tmp/t2.v 1

	echo "ok"
}

# vsqbs is non-interpolatory, don't test this way

echo "testing with $(basename $image)"
for i in nearest bicubic bilinear nohalo lbb; do
	test_rotate $image $i
done

test_thumbnail() {
	geo=$1
	correct_width=$2
	correct_height=$3

	printf "testing thumbnail -s $geo ... "
	$vipsthumbnail $image -s "$geo" -o $tmp/t1.jpg
	width=$(vipsheader -f width $tmp/t1.jpg)
	height=$(vipsheader -f height $tmp/t1.jpg)
	if [ $width -ne $correct_width ]; then
		echo width is $width, not $correct_width
		exit 1
	fi
	if [ $height -ne $correct_height ]; then
		echo width is $height, not $correct_height
		exit 1
	fi

	echo "ok"
}

test_thumbnail 100 100 75
test_thumbnail 100x100 100 75
test_thumbnail x100 133 100
test_thumbnail "100x100<" 1024 768
test_thumbnail "2000<" 2000 1500
test_thumbnail "100x100>" 100 75
test_thumbnail "2000>" 1024 768
