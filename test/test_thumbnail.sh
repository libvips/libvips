#!/bin/sh

# resize a 1000x1000 image to every size in [100,1000], check for black 

# see https://github.com/jcupitt/libvips/issues/131

# set -x

. ./variables.sh

# make a 1000x1000 mono test image ... add a bit so the image should not 
# contain any zeros, helps to spot missing tiles and bad pixels
echo building test image ...
$vips extract_band $image $tmp/t1.v 1
$vips linear $tmp/t1.v $tmp/t2.v 1 20 --uchar
$vips replicate $tmp/t2.v $tmp/t1.v 2 2
$vips crop $tmp/t1.v $tmp/t2.v 10 10 1000 1000

# is a difference beyond a threshold? return 0 (meaning all ok) or 1 (meaning
# error, or outside threshold)
break_threshold() {
	diff=$1
	threshold=$2
	return $(echo "$diff > $threshold" | bc -l)
}

size=1000
while [ $size -gt 99 ]; do
	printf "testing size to $size ... "
	$vipsthumbnail $tmp/t2.v -o $tmp/t1.v --size $size 
	if [ $($vipsheader -f width $tmp/t1.v) -ne $size ]; then
		echo $tmp/t1.v failed -- bad size
		echo output width is $($vipsheader -f width $tmp/t1.v) 
		exit
	fi
	if [ $($vipsheader -f height $tmp/t1.v) -ne $size ]; then
		echo $tmp/t1.v failed -- bad size
		echo output height is $($vipsheader -f width $tmp/t1.v) 
		exit
	fi

	$vips project $tmp/t1.v $tmp/cols.v $tmp/rows.v

	min=$($vips min $tmp/cols.v)
	if break_threshold $min 0; then
		echo $tmp/t1.v failed -- has a black column
		exit
	fi

	min=$($vips min $tmp/rows.v)
	if break_threshold $min 0; then
		echo $tmp/t1.v failed -- has a black row
		exit
	fi

	min=$($vips min $tmp/t1.v)
	if break_threshold $min 0; then
		echo $tmp/t1.v failed -- has black pixels
		exit
	fi

	echo ok

	size=$(($size-1))       
done



