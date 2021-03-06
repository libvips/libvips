#!/bin/bash

# code up the binary files in $1 as a set of name / string pairs 
# in $2

# we have to use arrays for the strings, since MSVC won't allow string
# literals larger than 64kb

in=$1
out=$2

echo "/* this file generated automatically, do not edit */" > $out
echo "" >> $out
echo "#include \"profiles.h\"" >> $out
echo "" >> $out

profile_names=
for file in $in/*.icm; do
  root=${file%.icm}
  base=${root##*/} 
  profile_name=vips__profile_fallback_$base
  profile_names="$profile_names $profile_name"
  echo "static VipsProfileFallback $profile_name = {" >> $out
  echo "    \"$base\"," >> $out
  echo "    $(stat --format=%s $file)," >> $out
  echo "    {" >> $out
  pigz -c -z -11 $file | hexdump -v -e '" 0x" 1/1 "%02X,"' | fmt >> $out
  echo "    }" >> $out
  echo "};" >> $out
  echo  >> $out
done

echo "VipsProfileFallback *vips__profile_fallback_table[] = {" >> $out
for profile_name in $profile_names; do
  echo "    &$profile_name," >> $out
done
echo "    NULL" >> $out
echo "};" >> $out
