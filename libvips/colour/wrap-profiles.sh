#!/bin/bash

# code up the binary files in $1 as a set of name / base64-encoded strings 
# in $2

in=$1
out=$2

echo "/* coded files, generated automatically */" > $out
echo "" >> $out
echo "#include \"profiles.h\"" >> $out
echo "" >> $out
echo "VipsCodedProfile vips__coded_profiles[] = {" >> $out
for file in $in/*; do 
  root=${file%.icm}
  base=${root##*/} 
  echo "    { \"$base\"," >> $out
  base64 $file | sed 's/\(.*\)/"\1"/g' >> $out
  echo "    }," >> $out
done
echo "    { 0, 0 }" >> $out
echo "};" >> $out
