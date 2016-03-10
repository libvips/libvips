#!/bin/sh

# resize a 1000x1000 image to every size in [500,1000] with every interpolator
# and check for black lines 

# see https://github.com/jcupitt/libvips/issues/131

# set -x

. ./variables.sh

# make a 1000x1000 mono test image
echo building test image ...
vips extract_band $image $tmp/t1.v 1
vips replicate $tmp/t1.v $tmp/t2.v 2 2
vips extract_area $tmp/t2.v $tmp/t1.v 10 10 1000 1000

# is a difference beyond a threshold? return 0 (meaning all ok) or 1 (meaning
# error, or outside threshold)
break_threshold() {
	diff=$1
	threshold=$2
	return $(echo "$diff > $threshold" | bc -l)
}

for interp in nearest bilinear bicubic lbb nohalo vsqbs; do
  size=1000
  while [ $size -gt 499 ]; do
    printf "testing $interp, size to $size ... "
    vipsthumbnail $tmp/t1.v -o $tmp/t2.v --size $size --interpolator $interp
    if [ $(vipsheader -f width $tmp/t2.v) -ne $size ]; then
      echo failed -- bad size
      echo output width is $(vipsheader -f width $tmp/t2.v) 
      exit
    fi
    if [ $(vipsheader -f height $tmp/t2.v) -ne $size ]; then
      echo failed -- bad size
      exit
    fi
    vips project $tmp/t2.v $tmp/cols.v $tmp/rows.v

    min=$(vips min $tmp/cols.v)
    if break_threshold $min 0; then
      echo failed -- has a black column
      exit
    fi
        
    min=$(vips min $tmp/rows.v)
    if break_threshold $min 0; then
      echo failed -- has a black row
      exit
    fi

    echo ok

    size=$(($size-1))       
  done
done
        


