#!/bin/sh

# set -x

. ./variables.sh 

chain=1

# im_benchmark needs a labq
$vips colourspace $image $tmp/t3.v labq

for tile in 10 64 128 512; do
	# benchmark includes a dither which will vary with tile size
	$vips --vips-concurrency=1 \
		--vips-tile-width=$tile --vips-tile-height=$tile \
		im_benchmarkn $tmp/t3.v $tmp/t5.v $chain

	for cpus in 2 3 4 5 6 7 8 99; do
		echo trying cpus = $cpus, tile = $tile ...
		$vips --vips-concurrency=$cpus \
			--vips-tile-width=$tile --vips-tile-height=$tile \
			im_benchmarkn $tmp/t3.v $tmp/t7.v $chain
		$vips subtract $tmp/t5.v $tmp/t7.v $tmp/t8.v
		$vips abs $tmp/t8.v $tmp/t9.v
		max=$($vips max $tmp/t9.v)
		if [ $(echo "$max > 0" | bc) -eq 1 ]; then
			break
		fi
	done
	if [ $(echo "$max > 0" | bc) -eq 1 ]; then
		break
	fi
done

if [ $(echo "$max > 0" | bc) -eq 1 ]; then
	echo error, max == $max
	exit 1
else
	echo all threading tests passed
fi

