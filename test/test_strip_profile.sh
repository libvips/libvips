#!/bin/bash
#
#  Prepare:
#  0. Check test-suite/images/sample.jpg includes xmp and icc_profile
#  1. Read image with xmp and icc profile
#  2. Save it with [] to no_strip.{jpg|png|webp}
#  3. Save it with [preserve=none] to strip.{jpg|png|webp}
#  4. Save it with [preserve=icc] to strip_keep.{jpg|png|webp}
#  5. Save it with [preserve=icc,profile=profile.icc] to strip_profile.{jpg|png|webp}
#  6. Save it with [profile=profile.icc] to another_profile.{jpg|png|webp}
#  
#  Tests:
#  Assert "no_strip.jpg" includes xmp and original ICC
#  Assert "strip.jpg" not includes icc-profile and xmp
#  Assert "strip_keep" not includes xmp and includes original ICC
#  Assert "strip-profile.jpg" with icc-profile and without xmp
#  Assert "another-profile.jpg" includes other icc_profile than original image (by size)
#
source ./variables.sh

srgb="${top_srcdir}/libvips/colour/profiles/sRGB.icm"

no_strip="${tmp}/no_strip"
strip="${tmp}/strip"
strip_keep="${tmp}/strip_keep_profile"
strip_profile="${tmp}/strip_profile"
another_profile="${tmp}/another_profile"

formats=(jpg webp png tif)

iccp_bytes() {
  $vipsheader -a "$1" \
  | grep "^icc-profile-data" \
  | cut -d: -f2 \
  | cut -d" " -f2
}

same_icc() {
  [ $(iccp_bytes $1) -eq $(iccp_bytes $2) ]
  echo $?
}

# returns 0 if xmp-data is missing
ch_xmp() {
  $vipsheader -a "$1" \
  | grep -c "^xmp-data"
} 

# returns 0 if icc-profile-data is missing
ch_iccp() {
  $vipsheader -a "$1" \
  | grep -c "^icc-profile-data" 
}

# Check original image contains xmp & icc
[ $(ch_xmp "${image}") -eq 0 ] && exit 1
[ $(ch_iccp "${image}") -eq 0 ] && exit 2

echo "${tmp}"
for f in ${formats[@]}; do
  # Create test images for format 
  # echo "----- no strip"
  $vips copy "${image}" "${no_strip}.${f}"
  # echo "----- strip"
  $vips copy "${image}" "${strip}.${f}[preserve=none]"
  # echo "----- strip_keep"
  $vips copy "${image}" "${strip_keep}.${f}[preserve=icc]"
  #echo "----- strip profile"
  $vips copy "${image}" "${strip_profile}.${f}[preserve=icc,profile=${srgb}]"
  #echo "----- another"
  $vips copy "${image}" "${another_profile}.${f}[profile=${srgb}]"

  echo -en "\nCheck no_strip.${f} includes xmp:"
    [ $(ch_xmp "${no_strip}.${f}") -eq 0 ] && printf "FAIL\n" $f && exit 1
  echo -en "\nCheck no_strip.${f} includes ICC:"
    [ $(ch_iccp "${no_strip}.${f}") -eq 0 ] && printf "FAIL\n" && exit 2
  echo -en "\nCheck no_strip.${f} includes original ICC:"
    [ $(same_icc "${no_strip}.${f}" "${image}") -ne 0 ] && printf "FAIL\n" && exit 3

  echo -en "\nCheck strip.${f} not includes xmp"
    [ $(ch_xmp "${strip}.${f}") -ne 0 ] && printf "FAIL\n" && exit 3
  echo -en "\nCheck strip.${f} not includes ICC"
    [ $(ch_iccp "${strip}.${f}") -ne 0 ] && printf "FAIL\n" && exit 4

  echo -en "\nCheck strip_keep_profile.${f} not includes xmp"
    [ $(ch_xmp "${strip_keep}.${f}") -ne 0 ] && printf "FAIL\n" && exit 5
  echo -en "\nCheck strip_keep_profile.${f} includes ICC"
    [ $(ch_iccp "${strip_keep}.${f}") -eq 0 ] && printf "FAIL\n" && exit 6
  echo -en "\nCheck strip_keep_profile.${f} includes original ICC:"
    [ $(same_icc "${strip_keep}.${f}" "${image}") -ne 0 ] && printf "FAIL\n" && exit 3

  echo -en "\nCheck strip_profile.${f} not includes xmp"
    [ $(ch_xmp "${strip_profile}.${f}") -ne 0 ] && printf "FAIL\n" && exit 7
  echo -en "\nCheck strip_profile.${f} includes ICC"
    [ $(ch_iccp "${strip_profile}.${f}") -eq 0 ] && printf "FAIL\n" && exit 8

  echo -en "\nCheck another_profile.${f} is not same size"
  [ $(same_icc "${another_profile}.${f}" "${image}") -eq 0 ] && printf "FAIL\n" && exit 8
done
echo -e "\n"

exit 0
