Title: Operator index > By section > Resample

<!-- libvips/resample -->

These operations build on each other in a set of layers.

First, [method@Image.affine] applies an affine transform to an image. This
is any sort of 2D transform which preserves straight lines; so any combination
of stretch, sheer, rotate and translate. You supply an interpolator for it to
use to generate pixels, see [ctor@Interpolate.new]. It will not produce good
results for very large shrinks: you'll see aliasing.

[method@Image.reduce] is like [method@Image.affine], but it can only shrink
images, it can't enlarge, rotate, or skew. It's very fast and uses an adaptive
kernel for interpolation.

[method@Image.shrink] is a fast block shrinker. It can quickly reduce images
by large integer factors. It will give poor results for small size reductions:
again, you'll see aliasing.

Next, [method@Image.resize] specialises in the common task of image reduce and
enlarge. It strings together combinations of [method@Image.shrink],
[method@Image.reduce], [method@Image.affine] and others to implement a general,
high-quality image resizer.

Finally, [ctor@Image.thumbnail] combines load and resize in one operation, and
adds colour management and correct handling of alpha transparency. Because
load and resize happen together, it can exploit tricks like JPEG and TIFF
shrink-on-load, giving a (potentially) huge speedup.
[method@Image.thumbnail_image] is only there for emergencies, don't use it
unless you really have to.

As a separate thing, [method@Image.mapim] can apply arbitrary 2D image
transforms to an image.

## Classes

* [class@Interpolate]

## Callbacks

* [callback@InterpolateMethod]

## Functions

* [method@Image.shrink]
* [method@Image.shrinkh]
* [method@Image.shrinkv]
* [method@Image.reduce]
* [method@Image.reduceh]
* [method@Image.reducev]
* [ctor@Image.thumbnail]
* [ctor@Image.thumbnail_buffer]
* [method@Image.thumbnail_image]
* [ctor@Image.thumbnail_source]
* [method@Image.similarity]
* [method@Image.rotate]
* [method@Image.affine]
* [method@Image.resize]
* [method@Image.mapim]
* [method@Image.quadratic]
* [func@interpolate]
* [ctor@Interpolate.new]
* [func@Interpolate.bilinear_static]
* [func@Interpolate.nearest_static]
* [method@Interpolate.get_method]
* [method@Interpolate.get_window_offset]
* [method@Interpolate.get_window_size]

## Constants

* [const@INTERPOLATE_SCALE]
* [const@INTERPOLATE_SHIFT]
* [const@TRANSFORM_SCALE]
* [const@TRANSFORM_SHIFT]

## Enumerations

* [enum@Kernel]
* [enum@Size]
