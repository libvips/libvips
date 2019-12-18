#!/bin/sh

# set -x
set -e

. ./variables.sh

if test_supported tiffload; then
	VIPS_STALL=1 $vips copy $image $tmp/x.tif
  cat > $tmp/mask.con <<EOF
3 3 8 0
-1 -1 -1
-1 16 -1
-1 -1 -1
EOF
	VIPS_STALL=1 $vips conv $tmp/x.tif $tmp/x2.tif $tmp/mask.con
fi
