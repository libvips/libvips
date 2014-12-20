#!/bin/sh

#set -x

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

	vips subtract $before $after $tmp/difference.v
	vips abs $tmp/difference.v $tmp/abs.v 
	dif=$(vips max $tmp/abs.v)

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

	vips affine $im $tmp/t1.v "$trn" --interpolate $inter
	vips affine $tmp/t1.v $tmp/t2.v "$trn" --interpolate $inter
	vips affine $tmp/t2.v $tmp/t1.v "$trn" --interpolate $inter
	vips affine $tmp/t1.v $tmp/t2.v "$trn" --interpolate $inter

	test_difference $im $tmp/t2.v 1

	echo "ok"
}

# vsqbs is non-interpolatory, don't test this way

echo "testing with $(basename $image)"
for i in nearest bicubic bilinear nohalo lbb; do
	test_rotate $image $i
done
