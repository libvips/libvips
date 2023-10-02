#!/bin/sh

#  Prepare:
#  0. Check test-suite/images/sample.jpg includes XMP and ICC profile
#  1. Read image with XMP and ICC profile
#  2. Save it with no options to keep_all.{jpg,png,webp,avif}
#  3. Save it with --keep=none to keep_none.{jpg,png,webp,avif}
#  4. Save it with --keep=icc to keep_icc.{jpg,png,webp,avif}
#  5. Save it with --keep=none --profile=profile.icc to keep_custom_icc.{jpg,png,webp,avif}
#
#  Tests:
#  Assert "keep_all.jpg" keep XMP and ICC
#  Assert "keep_none.jpg" strip XMP and ICC
#  Assert "keep_icc.jpg" keep original ICC profile
#  Assert "keep_custom_icc.jpg" keep custom ICC profile

# set -x
set -e

. ./variables.sh

srgb="$top_srcdir/libvips/colour/profiles/sRGB.icm"

keep_all="$tmp/keep_all"
keep_none="$tmp/keep_none"
keep_icc="$tmp/keep_icc"
keep_custom_icc="$tmp/keep_custom_icc"

iccp_base64() {
  $vipsheader -f "icc-profile-data" "$1"
}

same_icc() {
  [ "$(iccp_base64 $1)" = "$(iccp_base64 $2)" ] && echo 1 || echo 0
}

# returns 0 if xmp-data is missing
ch_xmp() {
  $vipsheader -f "xmp-data" $1 > /dev/null 2>&1 && echo 1 || echo 0
}

# returns 0 if icc-profile-data is missing
ch_iccp() {
  $vipsheader -f "icc-profile-data" $1 > /dev/null 2>&1 && echo 1 || echo 0
}

# Check original image contains XMP and ICC
[ $(ch_xmp "$image") -eq 0 ] && exit 1
[ $(ch_iccp "$image") -eq 0 ] && exit 2

echo "$tmp"
for saver in jpegsave webpsave pngsave tiffsave heifsave; do
  if ! test_supported $saver; then continue; fi

  f=${saver%"save"}

  # Prefer AVIF over HEIC
  if [ "$f" = "heif" ]; then f="avif"; fi

  # Create test images for format
  # echo "----- keep all"
  $vips $saver "$image" "$keep_all.$f"
  # echo "----- keep none"
  $vips $saver "$image" "$keep_none.$f" --keep=none
  # echo "----- keep icc"
  $vips $saver "$image" "$keep_icc.$f" --keep=icc
  # echo "----- custom ICC profile"
  $vips $saver "$image" "$keep_custom_icc.$f" --keep=none --profile=$srgb

  echo -n "Check keep_all.$f keep XMP: "
    [ $(ch_xmp "$keep_all.$f") -eq 0 ] && echo "FAIL" && exit 2 || echo "OK"
  echo -n "Check keep_all.$f keep ICC: "
    [ $(ch_iccp "$keep_all.$f") -eq 0 ] && echo "FAIL" && exit 3 || echo "OK"
  echo -n "Check keep_all.$f keep original ICC: "
    [ $(same_icc "$keep_all.$f" "$image") -eq 0 ] && echo "FAIL" && exit 4 || echo "OK"

  echo -n "Check keep_none.$f strip XMP: "
    [ $(ch_xmp "$keep_none.$f") -ne 0 ] && echo "FAIL" && exit 5 || echo "OK"
  echo -n "Check keep_none.$f strip ICC: "
    [ $(ch_iccp "$keep_none.$f") -ne 0 ] && echo "FAIL" && exit 6 || echo "OK"

  echo -n "Check keep_icc.$f strip XMP: "
    [ $(ch_xmp "$keep_icc.$f") -ne 0 ] && echo "FAIL" && exit 7 || echo "OK"
  echo -n "Check keep_icc.$f keep ICC: "
    [ $(ch_iccp "$keep_icc.$f") -eq 0 ] && echo "FAIL" && exit 8 || echo "OK"
  echo -n "Check keep_icc.$f keep original ICC: "
    [ $(same_icc "$keep_icc.$f" "$image") -eq 0 ] && echo "FAIL" && exit 9 || echo "OK"

  echo -n "Check keep_custom_icc.$f differ from original ICC: "
  [ $(same_icc "$keep_custom_icc.$f" "$image") -eq 1 ] && echo "FAIL" && exit 10 || echo "OK"
done

exit 0
