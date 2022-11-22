#!/bin/bash

# code up the binary files in $1 as a set of name / string pairs in $2
# For example:
# $ ./wrap-profiles.sh profiles profiles.c

# we have to use arrays for the strings, since MSVC won't allow string
# literals larger than 64kb

in=$1
out=$2

echo "/* this file is generated automatically, do not edit! */" > $out
echo "/* clang-format off */" > $out
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
  echo -e "\t\"$base\"," >> $out
  echo -e "\t$(stat --format=%s $file)," >> $out
  echo -e "\t{" >> $out
  pigz -c -z -11 $file | hexdump -v -e '" 0x" 1/1 "%02X,"' | fmt >> $out
  echo -e "\t}" >> $out
  echo "};" >> $out
  echo >> $out
done

echo "VipsProfileFallback *vips__profile_fallback_table[] = {" >> $out
for profile_name in $profile_names; do
  echo -e "\t&$profile_name," >> $out
done
echo -e "\tNULL" >> $out
echo "};" >> $out
