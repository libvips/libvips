#!/bin/bash

for filename in "$@"; do
  sed -i -f rename.sed $filename
done
