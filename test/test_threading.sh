#!/bin/sh

# set -x

source variables.sh 

chain=1

# im_benchmark needs a labq
vips im_sRGB2XYZ $image $tmp/t1.v
vips im_XYZ2Lab $tmp/t1.v $tmp/t2.v
vips im_Lab2LabQ $tmp/t2.v $tmp/t3.v

for tile in 10 64 128 512; do
	# benchmark includes a dither which will vary with tile size
	vips --vips-concurrency=1 \
		--vips-tile-width=$tile --vips-tile-height=$tile \
		im_benchmarkn $tmp/t3.v $tmp/t5.v $chain

	for cpus in 2 3 4 5 6 7 8 99 1024; do
		echo trying cpus = $cpus, tile = $tile ...
		vips --vips-concurrency=$cpus \
			--vips-tile-width=$tile --vips-tile-height=$tile \
			im_benchmarkn $tmp/t3.v $tmp/t7.v $chain
		vips im_subtract $tmp/t5.v $tmp/t7.v $tmp/t8.v
		vips im_abs $tmp/t8.v $tmp/t9.v
		max=`vips im_max $tmp/t9.v`
		if [ $max -gt 0 ]; then
			break
		fi
	done
	if [ $max -gt 0 ]; then
		break
	fi
done

if [ $max -gt 0 ]; then
	echo error, max == $max
	exit 1
else
	echo all threading tests passed
fi

