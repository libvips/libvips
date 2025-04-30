Title: Using > Multipage and animated images

libvips represents animated and multipage images as tall, thin strips of
frames, like a strip of movie film (or a roll of toilet paper). Special image
metadata items are used to hold the page height, the number of frames, and any
frame delay or loop settings.

At least the JXL, GIF and WebP loaders and savers support animation,
and the TIFF, PDF, HEIC, AVIF and VIPS loaders and savers support multipage.

## Reading multipage images

For example, at the command-line, try:

```bash
$ vipsheader -a silver-gear-cogs-animation-5.gif[n=-1]
silver-gear-cogs-animation-5.gif: 281x2560 uchar, 4 bands, srgb, gifload
width: 281
height: 2560
bands: 4
format: uchar
coding: none
interpretation: srgb
xoffset: 0
yoffset: 0
xres: 1
yres: 1
filename: silver-gear-cogs-animation-5.gif
vips-loader: gifload
page-height: 320
n-pages: 8
loop: 0
delay: 100 100 100 100 100 100 100 100
background: 0 0 0
gif-palette: -12500671 -11447983 -723724 -3289651 -11974327 -11711155 -5395027 -13027015 -9276814 -9408400 -16777216 -14079703 -197380 -12237499 -5723992 -526345 -15592942 -12763843 -5921371 -13750738 -13553359 -10592674 -6908266 -7829368 -7960954 -8158333 -809254
bits-per-sample: 7
palette: 1
```

Points to note:

- By default, libvips will just read the first page from an animated or
  multipage image. You pass `[n=-1]` to the loader to get all pages (or
  frames) in the animation. You can pick out a single page or range of
  pages with perhaps `[page=4]` and `[page=2,n=2]`.

- `page-height` is the vertical size of each frame within the overall image
  (2560 pixels high in this case).

- `n-pages` is the number of pages (or frames) in this animation. Obviously
  `n-pages * frame-height == height`, or in this case 320 * 8 == 2560.

- `loop` is the number of times the animation should loop before stopping.
  Zero means "never stop looping".

- `delay` is an optional array with a time in milliseconds which each frame
  should display for.

You'll see a similar set of metadata for a multipage image, such as a PDF:

```bash
$ vipsheader -a nipguide.pdf[n=-1]
nipguide.pdf: 595x48836 uchar, 4 bands, srgb, pdfload
width: 595
height: 48836
bands: 4
format: uchar
coding: none
interpretation: srgb
xoffset: 0
yoffset: 0
xres: 2.83465
yres: 2.83465
filename: nipguide.pdf
vips-loader: pdfload
page-height: 842
pdf-n_pages: 58
n-pages: 58
pdf-creator: TeX
pdf-producer: pdfTeX-1.40.16
```

Now there's no `loop` or `delay` since this is not animated, but `n-pages` and
`page-height` are set. In just the same way, you can load all pages, a single
page or a range of pages.

This all assumes that every page (or frame) has the same dimensions. If
they don't (this can commonly happen with PDF and TIFF), you have to read
pages one by one.

## Writing multipage images

As long as these various pieces of metadata are set, you can write animated
and multipage images in the obvious way. For example:

```bash
$ vips copy nipguide.pdf[n=-1] x.gif
```

This will take the 58-page PDF and render a 58-frame animation.  This only
works because this specific PDF has pages which are all the same size --
PDFs with (for example) a mix of portrait and landscape pages can't be
handled like this.

More usefully, you could convert a GIF to WebP with:

```bash
$ vips copy silver-gear-cogs-animation-5.gif[n=-1] silver.webp
```

To write an animated or multipage image programmatically, you need to
construct the tall, thin image and set the metadata. For example:

```bash
$ vips arrayjoin "k2.jpg k4a.png" x.tif[page-height=2048] --across=1
```

Provided that the images are both 2048 pixels high, this will write a
two-page TIFF.

In Python you could write something like:

```python
#!/usr/bin/env python3

import sys
import pyvips

# the input images -- assume these are all the same size
images = [pyvips.Image.new_from_file(filename, access="sequential")
          for filename in sys.argv[2:]]

# frame delays are in milliseconds
delay_array = [300] * len(images)

animation = pyvips.Image.arrayjoin(images, across=1).copy()
animation.set_type(pyvips.GValue.gint_type, "loop", 10)
animation.set_type(pyvips.GValue.gint_type, "n-pages", len(images))
animation.set_type(pyvips.GValue.gint_type, "page-height", images[0].height)
animation.set_type(pyvips.GValue.array_int_type, "delay", delay_array)
print(f"writing {sys.argv[1]} ...")
animation.write_to_file(sys.argv[1])
```

It's a little more fiddly in C:

```c
/* compile with
 *
 * gcc -g -Wall assemble-animated.c `pkg-config vips --cflags --libs`
 */

#include <stdlib.h>
#include <vips/vips.h>

/* for libvips before 8.16, add this line:
 *	G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsImage, g_object_unref)
 */

int
main(int argc, char *argv[])
{
    if (VIPS_INIT(argv[0]))
        vips_error_exit(NULL);
    if (argc < 3)
        vips_error_exit("usage: %s outfile infile1 infile2 ...", argv[0]);

    /* Load a set of input files.
     */
    g_autoptr(GPtrArray) frames = g_ptr_array_new_full(argc, g_object_unref);
    for (int i = 2; i < argc; i++) {
        VipsImage *frame;
        if (!(frame = vips_image_new_from_file(argv[i],
            "access", VIPS_ACCESS_SEQUENTIAL,
            NULL)))
            vips_error_exit(NULL);

        g_ptr_array_add(frames, frame);
    }

    /* Combine to form a vertical strip.
     */
    g_autoptr(VipsImage) strip;
    if (vips_arrayjoin((VipsImage **) frames->pdata, &strip, frames->len,
        "across", 1,
        NULL))
        vips_error_exit(NULL);

    /* Set the animation metadata. Delay times are in milliseconds.
     */
    VipsImage *frame0 = VIPS_IMAGE(frames->pdata[0]);
    vips_image_set_int(strip, "page-height", frame0->Ysize);
    vips_image_set_int(strip, "loop", 10);
    int delays[] = { 300, 300, 300 };
    vips_image_set_array_int(strip, "delay", delays, VIPS_NUMBER(delays));

    if (vips_image_write_to_file(strip, argv[1], NULL))
        vips_error_exit(NULL);

    return 0;
}
```
