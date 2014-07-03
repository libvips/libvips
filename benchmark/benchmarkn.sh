#!/bin/bash

uname -a
gcc --version
vips --version

# how large an image do you want to process? 
# sample2.v is 290x442 pixels ... replicate this many times horizontally and 
# vertically to get a highres image for the benchmark
tile=13

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
echo -n "test image is" `vipsheader -f width temp.v` 
echo " by" `vipsheader -f height temp.v` "pixels"
max_cpus=`vips im_concurrency_get`

echo "max cpus = $max_cpus"
echo "starting benchmark ..."
echo /usr/bin/time -f %e vips \
  --vips-concurrency=xx \
  im_benchmarkn temp.v temp2.v $chain
echo reported real-time is best of three runs
echo cpus real-time

for((cpus = 1; cpus <= max_cpus; cpus++)); do
  t1=`/usr/bin/time -f %e vips \
	  --vips-concurrency=$cpus \
	  im_benchmarkn temp.v temp2.v $chain 2>&1`
  if [ $? != 0 ]; then
    echo "benchmark failed -- install problem?"
    exit 1
  fi
  t2=`/usr/bin/time -f %e vips \
	  --vips-concurrency=$cpus \
	  im_benchmarkn temp.v temp2.v $chain 2>&1`
  t3=`/usr/bin/time -f %e vips \
	  --vips-concurrency=$cpus \
	  im_benchmarkn temp.v temp2.v $chain 2>&1`

  # echo $t1 $t2 $t3

  if [[ $t2 < $t1 ]]; then
	  t1=$t2
  fi
  if [[ $t3 < $t1 ]]; then
	  t1=$t3
  fi
  echo $cpus $t1
done
