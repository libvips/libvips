#!/bin/sh

# this has now been mostly superseded by test_foreign.py ... keep this around
# as a test of the command-line interface

# set -x
set -e

. ./variables.sh

# poppler / pdfload reference image
poppler=$test_images/blankpage.pdf
poppler_ref=$test_images/blankpage.pdf.png

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
	thresh=$4

	printf "testing $(basename $in) $format ... "

	$vips copy $ref $tmp/before.v
	$vips copy $in $tmp/after.v

	test_difference $tmp/before.v $tmp/after.v $thresh

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
	test_format $image png 90 [palette,colours=256,Q=100,dither=0,interlace=1]
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
	test_loader $poppler_ref $poppler pdfload 0
fi

# don't test SVG --- the output varies too much between librsvg versions

if test_supported gifload; then
	test_loader $giflib_ref $giflib gifload 0
fi

if test_supported matload; then
	test_loader $matlab_ref $matlab matlab 0

	# test blocked and untrusted
	printf "testing VIPS_BLOCK_UNTRUSTED with matio ... "
	export VIPS_BLOCK_UNTRUSTED=1
	if $vips matload $matlab $tmp/block.png; then
		echo "failed to block matload"
		exit 1
	fi
	echo "ok"
	unset VIPS_BLOCK_UNTRUSTED
fi

if test_supported dzsave; then
	test_saver dzsave $image .zip
	test_saver copy $image .dz
	test_saver copy $image .dz[container=zip]
fi

if test_supported jp2kload; then
	test_format $image jp2 20
	test_format $image jp2 0 [lossless]
fi
