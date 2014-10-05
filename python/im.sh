#!/bin/bash

convert $1 \
    -background Red -density 300 \
    -font /usr/share/fonts/truetype/msttcorefonts/Arial.ttf \
    -pointsize 12 -gravity south -splice 0x150 \
    -gravity southwest -annotate +50+50 "left corner" \
    -gravity southeast -annotate +50+50 'right corner' \
    +repage \
    $2
