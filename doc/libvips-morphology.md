Title: Operator index > By section > Morphology

<!-- libvips/morphology -->

The morphological functions search images for particular patterns of pixels,
specified with the mask argument, either adding or removing pixels when they
find a match. They are useful for cleaning up images --- for example, you
might threshold an image, and then use one of the morphological functions
to remove all single isolated pixels from the result.

If you combine the morphological operators with the mask rotators
([method@Image.rot45], for example) and apply them repeatedly, you can
achieve very complicated effects: you can thin, prune, fill, open edges,
close gaps, and many others. For example, see “Fundamentals of Digital
Image Processing” by A. Jain, pp 384-388, Prentice-Hall, 1989 for more
ideas.

Beware that libvips reverses the usual image processing convention, by
assuming white objects (non-zero pixels) on a black background (zero
pixels).

The mask you give to the morphological functions should contain only the
values 0 (for background), 128 (for don't care) and 255 (for object). The
mask must have odd length sides --- the origin of the mask is taken to be
the centre value. For example, the mask:

```c
VipsImage *mask = vips_image_new_matrixv(3, 3,
    128.0, 255.0, 128.0,
    255.0, 255.0, 255.0,
    128.0, 255.0, 128.0);
```

applied to an image with [method@Image.morph]
[enum@Vips.OperationMorphology.DILATE] will do a 4-connected dilation.

Dilate sets pixels in the output if any part of the mask matches, whereas
erode sets pixels only if all the mask matches.

See [method@Image.andimage], [method@Image.orimage] and
[method@Image.eorimage] for analogues of the usual set difference and set
union operations.

Use [ctor@Image.new_matrixv] to create a mask in source,
[ctor@Image.matrixload] to load a mask from a simple text file, and
[ctor@Image.mask_ideal] and friends to create square, circular and ring
masks of specific sizes.

## Functions

* [method@Image.morph]
* [method@Image.rank]
* [method@Image.median]
* [method@Image.countlines]
* [method@Image.labelregions]
* [method@Image.fill_nearest]

## Enumerations

* [enum@OperationMorphology]
