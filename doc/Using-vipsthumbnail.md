<refmeta>
  <refentrytitle>Using `vipsthumbnail`</refentrytitle>
  <manvolnum>3</manvolnum>
  <refmiscinfo>libvips</refmiscinfo>
</refmeta>

<refnamediv>
  <refname>`vipsthumbnail`</refname>
  <refpurpose>Introduction to `vipsthumbnail`, with examples</refpurpose>
</refnamediv>

libvips ships with a handy command-line image thumbnailer, `vipsthumbnail`.
This page introduces it, with some examples. 

The thumbnailing functionality is implemented by `vips_thumbnail()` and
`vips_thumbnail_buffer()` (which thumbnails an image held as a string),
see the docs for details. You can use these functions from any language
with a libvips binding. For example, from PHP you could write:

```php?start_inline=1 
$filename = "image.jpg";
$image = Vips\Image::thumbnail($filename, 200, ["height" => 200]);
$image->writeToFile("my-thumbnail.jpg");
```

You can also call `thumbnail_source` from the CLI, for example:

```bash
$ cat k2.jpg | \
    vips thumbnail_source [descriptor=0] .jpg[Q=90] 128 | \
    cat > x.jpg
```

# libvips options

`vipsthumbnail` supports the usual range of vips command-line options. A
few of them are useful:

`--vips-cache-trace` shows each operation as libvips starts it. It can be
handy to see exactly what operations `vipsthumbnail` is running for you.

`--vips-leak` turns on the libvips memory leak checker. As well as reporting
leaks (hopefully there are none) it also tracks and reports peak memory use.

`--vips-progress` runs a progress indicator during computation. It can be
useful to see where libvips is looping and how often.

`--vips-info` shows a higher level view of the operations that `vipsthumbnail`
is running. 

# Looping

`vipsthumbnail` can process many images in one command. For example:

```bash
$ vipsthumbnail *.jpg
```

will make a thumbnail for every jpeg in the current directory.  See the
[Output directory](#output-directory) section below to see how to change
where thumbnails are written.

`vipsthumbnail` will process images one after the other. You can get a good
speedup by running several `vipsthumbnail`s in parallel, depending on how
much load you want to put on your system. For example:

```bash
$ parallel vipsthumbnail ::: *.jpg
```

# Thumbnail size

You can set the bounding box of the generated thumbnail with the `--size`
option. For example:

```bash
$ vipsthumbnail shark.jpg --size 200x100
```

Use a single number to set a square bounding box. You can omit either number
but keep the x to mean resize just based on that axis, for example:

```bash
$ vipsthumbnail shark.jpg --size 200x
```

Will resize to 200 pixels across, no matter what the height of the input image
is. 

You can append `<` or `>` to mean only resize if the image is smaller or larger
than the target. 

You can append `!` to force a resize to the exact target size, breaking
the aspect ratio. 

# Cropping

`vipsthumbnail` normally shrinks images to fit within the box set by `--size`.
You can use the `--smartcrop` option to crop to fill the box instead. Excess
pixels are trimmed away using the strategy you set. For example:

```bash
$ vipsthumbnail owl.jpg --smartcrop attention -s 128
```

Where `owl.jpg` is an off-centre composition:

![](owl.jpg)

Gives this result:

![](tn_owl.jpg)

First it shrinks the image to get the vertical axis to 128 pixels, then crops
down to 128 pixels across using the `attention` strategy. This one searches
the image for features which might catch a human eye, see `vips_smartcrop()`
for details. 

# Linear light

Shrinking images involves combining many pixels into one. Arithmetic
averaging really ought to be in terms of the number of photons, but (for
historical reasons) the values stored in image files are usually related
to the voltage that should be applied to the electron gun in a CRT display.

`vipsthumbnail` has an option to perform image shrinking in linear space, that
is, a colourspace where values are proportional to photon numbers. For example:

```bash
$ vipsthumbnail fred.jpg --linear
```

The downside is that in linear mode, none of the very fast shrink-on-load
tricks that `vipsthumbnail` normally uses are possible, since the shrinking is
done at encode time, not decode time, and is done in terms of CRT voltage, not
photons. This can make linear light thumbnailing of large images extremely slow.

For example, for a 10,000 x 10,000 pixel JPEG I see:

```bash
$ time vipsthumbnail wtc.jpg 
real	0m0.317s
user	0m0.292s
sys	0m0.016s
$ time vipsthumbnail wtc.jpg --linear
real	0m4.660s
user	0m4.640s
sys	0m0.016s
```

# Output directory

You set the thumbnail write parameters with the `-o`
option. This is a pattern which the input filename is pasted into to
produce the output filename. For example:

```bash
$ vipsthumbnail fred.jpg jim.tif -o tn_%s.jpg
```

For each of the files to be thumbnailed, `vipsthumbnail` will drop the
extension (`.jpg` and `.tif` in this case) and then substitute the name into
the `-o` option, replacing the `%s` So this example will write thumbnails to
`tn_fred.jpg` and `tn_jim.jpg`.

If the pattern given to `-o` is an absolute path, any path components are
dropped from the input filenames. This lets you write all of your thumbnails
to a specific directory, if you want. For example:

```bash
$ vipsthumbnail fred.jpg ../jim.tif -o /mythumbs/tn_%s.jpg
```

Now both thumbnails will be written to `/mythumbs`, even though the source
images are in different directories.

Conversely, if `-o` is set to a relative path, any path component from the
input file is prepended. For example:

```bash
$ vipsthumbnail fred.jpg ../jim.tif -o mythumbs/tn_%s.jpg
```

Now both input files will have thumbnails written to a subdirectory of
their current directory.

# Output format and options

You can use `-o` to specify the thumbnail image format too. For example: 

```bash
$ vipsthumbnail fred.jpg ../jim.tif -o tn_%s.png
```

Will write thumbnails in PNG format.

You can give options to the image write operation as a list of comma-separated
arguments in square brackets. For example:

```bash
$ vipsthumbnail fred.jpg ../jim.tif -o tn_%s.jpg[Q=90,optimize_coding]
```

will write jpeg images with quality 90, and will turn on the libjpeg coding
optimizer.

Check the image write operations to see all the possible options. For example:

```
$ vips jpegsave
save image to jpeg file
usage:
   jpegsave in filename
where:
   in           - Image to save, input VipsImage
   filename     - Filename to save to, input gchararray
optional arguments:
   Q            - Q factor, input gint
			default: 75
			min: 1, max: 100
   profile      - Filename of ICC profile to embed, input gchararray
   optimize-coding - Compute optimal Huffman coding tables, input gboolean
			default: false
   interlace    - Generate an interlaced (progressive) jpeg, input gboolean
			default: false
   trellis-quant - Apply trellis quantisation to each 8x8 block, input gboolean
			default: false
   overshoot-deringing - Apply overshooting to samples with extreme values, input gboolean
			default: false
   optimize-scans - Split spectrum of DCT coefficients into separate scans, input gboolean
			default: false
   quant-table  - Use predefined quantization table with given index, input gint
			default: 0
			min: 0, max: 8
   subsample-mode - Select chroma subsample operation mode, input VipsForeignSubsample
			default enum: auto
			allowed enums: auto, on, off
   restart-interval - Add restart markers every specified number of mcu, input gint
			default: 0
			min: 0, max: 2147483647
   keep         - Which metadata to retain, input VipsForeignKeep
			default flags: exif:xmp:iptc:icc:other:all
			allowed flags: none, exif, xmp, iptc, icc, other, all
   background   - Background value, input VipsArrayDouble
```

The `keep` option is especially useful. Many image have very large IPTC,
ICC or XMP metadata items embedded in them, and removing these can give a
large saving.

For example:

```
$ vipsthumbnail 42-32157534.jpg
$ ls -l tn_42-32157534.jpg
-rw-r–r– 1 john john 6682 Nov 12 21:27 tn_42-32157534.jpg
```

`keep=none` almost halves the size of the thumbnail:

```
$ vipsthumbnail 42-32157534.jpg -o x.jpg[optimize_coding,keep=none]
$ ls -l x.jpg
-rw-r–r– 1 john john 3600 Nov 12 21:27 x.jpg
```

# Colour management

`vipsthumbnail` will optionally put images through LittleCMS for you. You can
use this to move all thumbnails to the same colour space. All web browsers
assume that images without an ICC profile are in sRGB colourspace, so if
you move your thumbnails to sRGB, you can strip all the embedded profiles.
This can save several kb per thumbnail.

For example:

```
$ vipsthumbnail shark.jpg
$ ls -l tn_shark.jpg 
-rw-r–r– 1 john john 7295 Nov  9 14:33 tn_shark.jpg
```

Now transform to sRGB and don't attach a profile (you can also use
`keep=none`, though that will remove *all* metadata from the image):

```
$ vipsthumbnail shark.jpg --export-profile srgb -o tn_shark.jpg[profile=none]
$ ls -l tn_shark.jpg 
-rw-r–r– 1 john john 4229 Nov  9 14:33 tn_shark.jpg
```

(You can use the filename of any RGB profile. The magic string `srgb` selects a
high-quality sRGB profile that's built into libvips.)

`tn_shark.jpg` will look identical to a user, but it's almost half the size. 

You can also specify a fallback input profile to use if the image has no
embedded one. For example, perhaps you somehow know that a JPG is in Adobe98
space, even though it has no embedded profile. 


```bash
$ vipsthumbnail kgdev.jpg --input-profile /my/profiles/a98.icm 
```

# Final suggestion

Putting all this together, I suggest this as a sensible set of options:

```bash
$ vipsthumbnail fred.jpg \
    --size 128 \
    --export-profile srgb \
    -o tn_%s.jpg[optimize_coding,keep=none] 
```
