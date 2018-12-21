#!/bin/bash

# code up the binary files in $1 as a set of base64-encoded strings in $2

in=$1
out_c=$2.c
out_h=$2.h

echo "/* coded files, generated automatically */" > $out_c
echo "" >> $out_c
for file in $in/*; do 
  root=${file%.icm}
  base=${root##*/} 
  echo char \*vips__coded_$base = >> $out_c
  base64 $file | sed 's/\(.*\)/"\1"/g' >> $out_c
  echo ';' >> $out_c
done

echo "/* header for coded files, generated automatically */" > $out_h
echo "" >> $out_h
for file in $in/*; do 
  root=${file%.icm}
  base=${root##*/} 
  echo extern char \*vips__coded_$base ';' >> $out_h
done


