Title: Operator index > By section > Mosaicing

<!-- libvips/mosaicing -->

These functions are useful for joining many small images together to make one
large image. They can cope with unstable contrast and arbitrary sub-image
layout, but will not do any geometric correction. Geometric errors should be
removed before using these functions.

The mosaicing functions can be grouped into layers:

The lowest level operation is [method@Image.merge] which joins two images
together left-right or up-down with a smooth seam.

Next, [method@Image.mosaic] uses search functions plus the two low-level merge
operations to join two images given just an approximate overlap as a start
point.

[method@Image.mosaic1] is a first-order analogue of the basic mosaic
functions: it takes two approximate tie-points and uses them to rotate and
scale the right-hand or bottom image before starting to join.

Finally, [method@Image.globalbalance] can be used to remove contrast
differences in a mosaic which has been assembled with these functions. It
takes the mosaic apart, measures image contrast differences along the seams,
finds a set of correction factors which will minimise these differences, and
reassembles the mosaic. [method@Image.remosaic] uses the same techniques, but
will reassemble the image from a different set of source images.

## Functions

* [method@Image.merge]
* [method@Image.mosaic]
* [method@Image.mosaic1]
* [method@Image.match]
* [method@Image.globalbalance]
* [method@Image.remosaic]
* [method@Image.matrixinvert]
* [method@Image.matrixmultiply]
