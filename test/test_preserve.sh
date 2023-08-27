#!/bin/sh

#  Prepare:
#  0. Check test-suite/images/sample.jpg includes XMP and ICC profile
#  1. Read image with XMP and ICC profile
#  2. Save it with no options to preserve_all.{jpg,png,webp,avif}
#  3. Save it with --preserve=none to preserve_none.{jpg,png,webp,avif}
#  4. Save it with --preserve=icc to preserve_icc.{jpg,png,webp,avif}
#  5. Save it with --preserve=none --profile=profile.icc to preserve_custom_icc.{jpg,png,webp,avif}
#
#  Tests:
#  Assert "preserve_all.jpg" preserve XMP and ICC
#  Assert "preserve_none.jpg" strip XMP and ICC
#  Assert "preserve_icc.jpg" preserve original ICC profile
#  Assert "preserve_custom_icc.jpg" preserve custom ICC profile

# set -x
set -e

. ./variables.sh

srgb="$top_srcdir/libvips/colour/profiles/sRGB.icm"

preserve_all="$tmp/preserve_all"
preserve_none="$tmp/preserve_none"
preserve_icc="$tmp/preserve_icc_profile"
preserve_custom_icc="$tmp/preserve_custom_icc"

savers=(jpegsave webpsave pngsave tiffsave heifsave)

iccp_base64() {
  $vipsheader -f "icc-profile-data" "$1"
}

same_icc() {
  [ "$(iccp_base64 $1)" = "$(iccp_base64 $2)" ] && echo 1 || echo 0
}

# returns 0 if xmp-data is missing
ch_xmp() {
  $vipsheader -f "xmp-data" "$1" &> /dev/null && echo 1 || echo 0
}

# returns 0 if icc-profile-data is missing
ch_iccp() {
  $vipsheader -f "icc-profile-data" "$1" &> /dev/null && echo 1 || echo 0
}

# Check original image contains xmp & icc
[ "$(ch_xmp "$image")" -eq 0 ] && exit 1
[ "$(ch_iccp "$image")" -eq 0 ] && exit 2

echo "$tmp"
for saver in ${savers[@]}; do
  if ! test_supported $saver; then continue; fi

  f=${saver%"save"}

  # Prefer AVIF over HEIC
  if [ "$f" = "heif" ]; then f="avif"; fi

  # Create test images for format
  # echo "----- preserve all"
  $vips $saver "$image" "$preserve_all.$f"
  # echo "----- preserve none"
  $vips $saver "$image" "$preserve_none.$f" --preserve=none
  # echo "----- preserve icc"
  $vips $saver "$image" "$preserve_icc.$f" --preserve=icc
  # echo "----- custom ICC profile"
  $vips $saver "$image" "$preserve_custom_icc.$f" --preserve=none --profile=$srgb

  echo -en "\nCheck preserve_all.$f preserve XMP: "
    [ $(ch_xmp "$preserve_all.$f") -eq 0 ] && echo -n "FAIL" $f && exit 1 || echo -n "OK"
  echo -en "\nCheck preserve_all.$f preserve ICC: "
    [ $(ch_iccp "$preserve_all.$f") -eq 0 ] && echo -n "FAIL" && exit 2 || echo -n "OK"
  echo -en "\nCheck preserve_all.$f preserve original ICC: "
    [ $(same_icc "$preserve_all.$f" "$image") -eq 0 ] && echo -n "FAIL" && exit 3 || echo -n "OK"

  echo -en "\nCheck preserve_none.$f strip XMP: "
    [ $(ch_xmp "$preserve_none.$f") -ne 0 ] && echo -n "FAIL" && exit 4 || echo -n "OK"
  echo -en "\nCheck preserve_none.$f strip ICC: "
    [ $(ch_iccp "$preserve_none.$f") -ne 0 ] && echo -n "FAIL" && exit 5 || echo -n "OK"

  echo -en "\nCheck preserve_icc_profile.$f strip XMP: "
    [ $(ch_xmp "$preserve_icc.$f") -ne 0 ] && echo -n "FAIL" && exit 6 || echo -n "OK"
  echo -en "\nCheck preserve_icc_profile.$f preserve ICC: "
    [ $(ch_iccp "$preserve_icc.$f") -eq 0 ] && echo -n "FAIL" && exit 7 || echo -n "OK"
  echo -en "\nCheck preserve_icc_profile.$f preserve original ICC: "
    [ $(same_icc "$preserve_icc.$f" "$image") -eq 0 ] && echo -n "FAIL" && exit 8 || echo -n "OK"

  echo -en "\nCheck preserve_custom_icc.$f differ from original ICC: "
  [ $(same_icc "$preserve_custom_icc.$f" "$image") -eq 1 ] && echo -n "FAIL" && exit 9 || echo -n "OK"
done
echo -e "\n"

exit 0
