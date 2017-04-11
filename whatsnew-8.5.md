libvips 8.5 should be out by the end of March 2017. This page introduces the 
main features. 

## New operators

Almost all of the logic from the `vipsthumbnail` program is now in a pair of
new operators, `vips_thumbnail()` and `vips_thumbnail_buffer()`. These are very
handy for the various scripting languages with vips bindings: you can now make
a high-quality, high-speed thumbnail in PHP (for example) with just:

```php
$filename = ...;
$image = Vips\Image::thumbnail($filename, 200, ["height" => 200]);
$image.writeToFile("my-thumbnail.jpg");
```

The new thumbnail operator has also picked up some useful features:

* **Smart crop** A new cropping mode called `attention` searches the image for
  edges, skin tones and areas of saturated colour, and attempts to position the
  crop box over the most significant feature. There's a `vips_smartcrop()`
  operator as well.

* **Crop constraints** Thanks to tomasc, libvips has crop constraints. You 
  can set it to only thumbnail if the image is larger or smaller than the target 
  (the `<` and `>` modifiers in imagemagick), and to crop to a width or height. 

* **Buffer sources** `vips_thumbnail_buffer()` will thumbnail an image held as 
  a formatted block of data in memory. This is useful for cloud services, where 
  the filesystem is often rather slow.

CLAHE, or Contrast-Limited Adaptive Histogram Equalisation, is a simple way to
make local histogram equalisation more useful. 

Plain local equalization removes
all global brightness variation and can make images hard to understand. 
The `hist_local` operator now has a `max-slope` parameter you can use to limit
how much equalisation can alter your image. A value of 3 generally works well.

## Toilet roll images

libvips used to let you pick single pages out of multi-page images, such
as PDFs, but had little support for processing entire documents.

libvips 8.5 now has good support for toilet roll images. You can load a 
multipage image as a very tall, thin strip, process the whole thing, and write
back to another multi-page file. The extra feature is an `n` parameter which
gives the number of pages to load, or -1 to load all pages. 

For example, (OME-
TIFF)[https://www.openmicroscopy.org/site/support/ome-model/ome-tiff]
is a standard for microscopy data that stores volumetric images as multi-page
TIFFs. They have some (sample
data)[https://www.openmicroscopy.org/site/support/ome-model/ome-tiff/data.html]
including a 4D image of an embryo. 

Each TIFF contains 10 slices. Normally you just see page 0:

```
$ vipsheader tubhiswt_C0_TP13.ome.tif
tubhiswt_C0_TP13.ome.tif: 512x512 uchar, 1 band, b-w, tiffload
```

Use `n=-1` and you see all the pages as a very tall strip:

```
$ vipsheader tubhiswt_C0_TP13.ome.tif[n=-1]
tubhiswt_C0_TP13.ome.tif: 512x5120 uchar, 1 band, b-w, tiffload
```

You can work with PDF, TIFF, GIF and all imagemagick-supported formats in 
this way. 

You can write this tall strip to another file, and it will be broken up into
pages:

```
$ vips copy tubhiswt_C0_TP13.ome.tif[n=-1] x.tif
$ vipsheader x.tif 
x.tif: 512x512 uchar, 1 band, b-w, tiffload
$ vipsheader x.tif[n=-1]
x.tif: 512x5120 uchar, 1 band, b-w, tiffload
```

The extra magic is a `page-height` property that images carry around that says
how long each sheet of toilet paper is. 

There are clearly some restrictions with this style of multi-page document 
handling: all pages must have identical width, height and colour depth; and image
processing operators have no idea they are dealing with a multi-page document,
so if you do something like `resize`, you'll need to update `page-height`. 
You'll also need to be careful about edge effects if you're using spatial 
filters.

## Computation reordering

Thanks to the developer of
(PhotoFlow)[https://github.com/aferrero2707/PhotoFlow], a non-destructive image 
editor with a libvips backend, libvips can now reorder computations to reduce
recalculation. This can (sometimes) produce a dramatic speedup.

This has been (discussed on the libvips 
blog)[http://libvips.blogspot.co.uk/2017/01/automatic-computation-reordering.html], 
but briefly, the order in which operator arguments are evaluated can have a
big effect on runtime due to the way libvips tries to cache and reuse results
behind the scenes. 

The blog post has some examples and some graphs.

## New sequential mode

libvips sequential mode has been around for a while. This is the thing libvips
uses to stream pixels through your computer, from input file to output file,
without having to have the whole image in memory all at the same time. When it
works, it give a nice performance boost and a large drop in memory use. 

There are some more complex cases where it didn't work. Consider this Python
program:

```python 
#!/usr/bin/python

import sys 
import random

import gi 
gi.require_version('Vips', '8.0') 
from gi.repository import Vips

composite = Vips.Image.black(10000, 10000)

for filename in sys.argv[2:]:
    tile = Vips.Image.new_from_file(filename, access = Vips.Access.SEQUENTIAL)
    x = random.randint(0, composite.width - tile.width) 
    y = random.randint(0, composite.height - tile.height) 
    composite = composite.insert(tile, x, y)

composite.write_to_file(sys.argv[1]) 
```

It makes a large 10,000 x 10,000 pixel image, then inserts all of the images
you list at random positions, then writes the result. 

You'd think this could work with sequential mode, but sadly with earlier
libvipses it will sometimes fail. The problem is that images can cover each 
other, so while writing, libvips can discover that it only needs the bottom few
pixels of one of the input images. The image loaders used to track the current
read position, and if a request came in for some pixels way down the image,
they'd assume one of the evaluation threads had run ahead of the rest and
needed to be stalled. Once stalled, it was only restarted on a long timeout,
causing performance to drop through the floor. 

libvips 8.5 has a new implementation of sequential mode that changes the way
threads are kept together as images are processed. Rather than trying to add
constraints to load operations, instead it puts the constraints into operations
that can cause threads to become spread out, such as vertical shrink.

As a result of this change, many more things can run in sequential mode, and
out of order reads should be impossible. 

## `libxml2` swapped out for `expat`

libvips has used libxml2 as its XML parser since dinosaurs roamed the Earth.
Now libvips is based on gobject, the XML parser selected by glib, expat, makes
more sense, since it will already be linked.

It's nice to be able to remove a required dependency for a change. 

## File format support

As usual, there are a range of improvements to file format read and write. 

* Thanks to a push from Felix Bünemann, TIFF now supports load and save to and
  from memory buffers. 
* `dzsave` can write to memory (as a zip file) as well.
* Again, thanks to pushing from Felix, libvips now supports ICC, XMP and IPCT
  metadata for WebP images. 
* FITS images support `bzero` and `bscale`.
* `tiffload` memory use is now much lower for images with large strips.

## Other

Many small bug fixes, improvements to the C++ binding. As usual, the 
ChangeLog has more detail, if you're interested.
