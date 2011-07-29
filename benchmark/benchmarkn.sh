#!/bin/sh

uname -a
gcc --version
vips --version

# how large an image do you want to process? 
# sample2.v is 290x442 pixels ... replicate this many times horizontally and 
# vertically to get a highres image for the benchmark
tile=2

# how complex an operation do you want to run?
# this sets the number of copies of the benchmark we chain together:
# higher values run more slowly and are more likely to be CPU-bound
chain=1

echo building test image ...
echo "tile=$tile"
vips im_replicate sample2.v temp.v $tile $tile
if [ $? != 0 ]; then
  echo "build of test image failed -- out of disc space?"
  exit 1
fi
echo -n "test image is" `header -f Xsize temp.v` 
echo " by" `header -f Ysize temp.v` "pixels"

echo "starting benchmark ..."
echo "chain=$chain"

for cpus in 1 2 3 4 ; do
  export IM_CONCURRENCY=$cpus

  echo IM_CONCURRENCY=$IM_CONCURRENCY
  echo time -p vips im_benchmarkn temp.v temp2.v $chain
  time -p vips im_benchmarkn temp.v temp2-$cpus.v $chain

  if [ $? != 0 ]; then
    echo "benchmark failed -- install problem?"
    exit 1
  fi

  # find pixel average ... should be the same for all IM_CONCURRENCY settings
  # or we have some kind of terrible bug
  echo vips im_avg temp2-$cpus.v
  vips im_avg temp2-$cpus.v
done
