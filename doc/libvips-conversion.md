Title: Operator index > By section > Conversion

<!-- libvips/conversion -->

These operations convert an image in some way. They can be split into two
main groups.

The first set of operations change an image's format in some way. You can
change the band format (for example, cast to 32-bit unsigned int), form
complex images from real images, convert images to matrices and back, change
header fields, and a few others.

The second group move pixels about in some way. You can flip, rotate,
extract, insert and join pairs of images in various ways.

## Functions

* [method@Image.copy]
* [method@Image.tilecache]
* [method@Image.linecache]
* [method@Image.sequential]
* [method@Image.copy_file]
* [method@Image.embed]
* [method@Image.gravity]
* [method@Image.flip]
* [method@Image.insert]
* [method@Image.join]
* [func@Image.arrayjoin]
* [method@Image.extract_area]
* [method@Image.crop]
* [method@Image.smartcrop]
* [method@Image.extract_band]
* [method@Image.replicate]
* [method@Image.grid]
* [method@Image.transpose3d]
* [method@Image.wrap]
* [method@Image.rot]
* [method@Image.rot90]
* [method@Image.rot180]
* [method@Image.rot270]
* [method@Image.rot45]
* [method@Image.autorot_remove_angle]
* [method@Image.autorot]
* [method@Image.zoom]
* [method@Image.subsample]
* [method@Image.cast]
* [method@Image.cast_uchar]
* [method@Image.cast_char]
* [method@Image.cast_ushort]
* [method@Image.cast_short]
* [method@Image.cast_uint]
* [method@Image.cast_int]
* [method@Image.cast_float]
* [method@Image.cast_double]
* [method@Image.cast_complex]
* [method@Image.cast_dpcomplex]
* [method@Image.scale]
* [method@Image.msb]
* [method@Image.byteswap]
* [func@Image.bandjoin]
* [method@Image.bandjoin2]
* [method@Image.bandjoin_const]
* [method@Image.bandjoin_const1]
* [func@Image.bandrank]
* [method@Image.bandfold]
* [method@Image.bandunfold]
* [method@Image.bandbool]
* [method@Image.bandand]
* [method@Image.bandor]
* [method@Image.bandeor]
* [method@Image.bandmean]
* [method@Image.recomb]
* [method@Image.ifthenelse]
* [func@Image.switch]
* [method@Image.flatten]
* [method@Image.addalpha]
* [method@Image.premultiply]
* [method@Image.unpremultiply]
* [func@Image.composite]
* [method@Image.composite2]
* [method@Image.falsecolour]
* [method@Image.gamma]

## Enumerations

* [enum@Extend]
* [enum@CompassDirection]
* [enum@Direction]
* [enum@Align]
* [enum@Angle]
* [enum@Angle45]
* [enum@Interesting]
* [enum@BlendMode]
