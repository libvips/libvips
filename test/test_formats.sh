#!/bin/sh

# this has now been mostly superceeded by test_foreign.py ... keep this around
# as a test of the command-line interface

# set -x
set -e

. ./variables.sh

# poppler / pdfload reference image
poppler=$test_images/blankpage.pdf
poppler_ref=$test_images/blankpage.png

# rsvg / svgload reference image
rsvg=$test_images/blankpage.svg
rsvg_ref=$test_images/blankpage.png

# giflib / gifload reference image
giflib=$test_images/trans-x.gif
giflib_ref=$test_images/trans-x.png

# the matlab image and reference image
matlab=$test_images/sample.mat
matlab_ref=$test_images/sample.png

# make a mono image
$vips extract_band $image $tmp/mono.v 1
mono=$tmp/mono.v

# make a radiance image
$vips float2rad $image $tmp/rad.v 
rad=$tmp/rad.v

# make a cmyk image
$vips bandjoin "$image $tmp/mono.v" $tmp/t1.v
$vips copy $tmp/t1.v $tmp/cmyk.v --interpretation cmyk
cmyk=$tmp/cmyk.v

# save to t1.format, load as back.v
save_load() {
	in=$1
	format=$2
	mode=$3

	if ! $vips copy $in $tmp/t1.$format$mode ; then
		echo "write to $out failed"
		exit 1
	fi

	if ! $vips copy $tmp/t1.$format $tmp/back.v ; then
		echo "read from $tmp/t1.format failed"
		echo "  (was written by $vips copy $in $tmp/t1.$format$mode)"
		exit 1
	fi
}

# is a difference beyond a threshold? return 0 (meaning all ok) or 1 (meaning
# error, or outside threshold)
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
		echo "save / load difference is $dif"
		exit 1
	fi
}

# save to the named file in tmp, convert back to vips again, subtract, look
# for max difference less than a threshold
test_format() {
	in=$1
	format=$2
	threshold=$3
	mode=$4

	printf "testing $(basename $in) $format$mode ... "

	save_load $in $format $mode
	test_difference $in $tmp/back.v $threshold

	echo "ok"
}

# as above, but hdr format
# this is a coded format, so we need to rad2float before we can test for
# differences
test_rad() {
	in=$1

	printf "testing $(basename $in) hdr ... "

	save_load $in hdr

	$vips rad2float $in $tmp/before.v
	$vips rad2float $tmp/back.v $tmp/after.v

	test_difference $tmp/before.v $tmp/after.v 0

	echo "ok"
}

# as above, but raw format
# we can't use suffix stuff to pick the load/save
test_raw() {
	in=$1

	printf "testing $(basename $in) raw ... "

	$vips copy $in $tmp/before.v
	width=$($vipsheader -f width $tmp/before.v)
	height=$($vipsheader -f height $tmp/before.v)
	bands=$($vipsheader -f bands $tmp/before.v)

	$vips rawsave $tmp/before.v $tmp/raw
	$vips rawload $tmp/raw $tmp/after.v $width $height $bands

	test_difference $tmp/before.v $tmp/after.v 0

	echo "ok"
}

# a format for which we only have a load (eg. matlab)
# pass in a reference file as well and compare to that
test_loader() {
	ref=$1
	in=$2
	format=$3

	printf "testing $(basename $in) $format ... "

	$vips copy $ref $tmp/before.v
	$vips copy $in $tmp/after.v

	test_difference $tmp/before.v $tmp/after.v 0

	echo "ok"
}

# a format for which we only have a saver (eg. dzsave)
# just run the operation and check exit status
test_saver() {
	oper=$1
	in=$2
	suffix=$3

	printf "testing $oper $(basename $in) $suffix ... "

	rm -rf $tmp/savertest*
	cmd="$vips $oper $in $tmp/savertest$suffix"
	if !  $cmd ; then
		echo "error executing:"
		echo "   $cmd"
		exit 1
	fi

	echo "ok"
}

# test for file format supported
test_supported() {
	format=$1

	if $vips $format > /dev/null 2>&1; then
		result=0
	else
		echo "support for $format not configured, skipping test"
		result=1
	fi

	return $result
}

test_format $image v 0
if test_supported tiffload; then
	test_format $image tif 0
	test_format $image tif 90 [compression=jpeg]
	test_format $image tif 0 [compression=deflate]
	test_format $image tif 0 [compression=packbits]
	test_format $image tif 90 [compression=jpeg,tile]
	test_format $image tif 90 [compression=jpeg,tile,pyramid]
fi
if test_supported pngload; then
	test_format $image png 0
	test_format $image png 0 [compression=9,interlace=1]
fi
if test_supported jpegload; then
	test_format $image jpg 90
fi
if test_supported webpload; then
	test_format $image webp 90
fi
test_format $image ppm 0
test_format $image pfm 0
if test_supported fitsload; then
	test_format $image fits 0
fi

# csv can only do mono
test_format $mono csv 0

# cmyk jpg is a special path
if test_supported jpegload; then
	test_format $cmyk jpg 90
fi
if test_supported tiffload; then
	test_format $cmyk tif 0
	test_format $cmyk tif 90 [compression=jpeg]
	test_format $cmyk tif 90 [compression=jpeg,tile]
	test_format $cmyk tif 90 [compression=jpeg,tile,pyramid]
fi

test_rad $rad 

test_raw $mono 
test_raw $image 

if test_supported pdfload; then
	test_loader $poppler_ref $poppler pdfload
fi

if test_supported svgload; then
	test_loader $rsvg_ref $rsvg svgload
fi

if test_supported gifload; then
	test_loader $giflib_ref $giflib gifload
fi

if test_supported matload; then
	test_loader $matlab_ref $matlab matlab
fi

if test_supported dzsave; then
	test_saver dzsave $image .zip
	test_saver copy $image .dz
	test_saver copy $image .dz[container=zip]
fi
