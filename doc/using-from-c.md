Title: Using > C

libvips comes with a convenient, high-level C API. You should read the API
docs for full details, but this section will try to give a brief overview.

## Library startup

When your program starts, use [func@INIT] to start up libvips. You
should pass it the name of your program, usually `argv[0]`. If
you call [func@shutdown] just before you exit, libvips will attempt to free
all resources. This can help leak checking, but is not required.

[func@INIT] is a macro to let it check that the libvips shared library you
have linked to matches the libvips headers you included.

You can add the libvips flags to your [class@GObject.Object] command-line
processing with [func@add_option_entries].

## The [class@Image] class

The basic data object is the [class@Image]. You can create an image from a
file on disc or from an area of memory, either as a C-style array, or as a
formatted object, like JPEG. See [ctor@Image.new_from_file] and friends.
Loading an image is fast: libvips read just enough of the image to be able
to get the various properties, such as width, but no decoding occurs until
pixel values are really needed.

Once you have an image, you can get properties from it in the usual
way. You can use projection functions, like [method@Image.get_width] or
[method@GObject.Object.get], to get [class@GObject.Object] properties. All
libvips objects are immutable, meaning you can only get properties, you
can't set them. See [libvips Header](file-format.html) to read about image
properties.

## Reference counting

libvips is based on the [class@GObject.Object] library and is therefore
reference counted. [ctor@Image.new_from_file] returns an object with a count
of 1. When you are done with an image, use [method@GObject.Object.unref] to
dispose of it. If you pass an image to an operation and that operation needs
to keep a copy of the image, it will ref it. So you can unref an image as soon
as you no longer need it, you don't need to hang on to it in case anyone else
is still using it.

See [class@Operation] for more details on libvips' reference counting
conventions. See the [Reference pools](#reference-pools) section below
for a way to automate reference counting in C.

## libvips operations

Use things like [method@Image.embed] to manipulate your images. You use it
from C like this:

```c
const char *filename;
VipsImage *in = vips_image_new_from_file(filename, NULL);
const int x = 10;
const int y = 10;
const int width = 1000;
const int height = 1000;
VipsImage *out;

if (vips_embed(in, &out, x, y, width, height, NULL))
    error_handling();
```

Now `out` will hold a reference to a 1000 by 1000 pixel image, with `in`
pasted 10 right and 10 down from the top left-hand corner. The remainder
of the image will be black. If `in` is too large, it will be clipped at
the image edges.

Operations can take optional arguments. You give these as a set of
NULL-terminated name-value pairs at the end of the call. For example,
you can write:

```c
if (vips_embed(in, &out, x, y, width, height,
               "extend", VIPS_EXTEND_COPY,
               NULL))
    error_handling();
```

And now the new edge pixels, which were black, will be filled with a copy
of the edge pixels of `in`. Operation options are listed at the top of each
operation's entry in the docs. Alternatively, the `vips` program is handy
for getting a summary of an operation's parameters. For example:

```bash
$ vips embed
embed an image in a larger image
usage:
   embed in out x y width height [--option-name option-value ...]
where:
   in           - Input image, input VipsImage
   out          - Output image, output VipsImage
   x            - Left edge of input in output, input gint
                      default: 0
                      min: -1000000000, max: 1000000000
   y            - Top edge of input in output, input gint
                      default: 0
                      min: -1000000000, max: 1000000000
   width        - Image width in pixels, input gint
                      default: 1
                      min: 1, max: 1000000000
   height       - Image height in pixels, input gint
                      default: 1
                      min: 1, max: 1000000000
optional arguments:
   extend       - How to generate the extra pixels, input VipsExtend
                      default enum: black
                      allowed enums: black, copy, repeat, mirror, white, background
   background   - Colour for background pixels, input VipsArrayDouble
```

See [class@Operation] for more information on running operations on images.

The API docs have a [handy table of all libvips operations](
function-list.html), if you want to find out how to do something, try
searching that.

When you are done, you can write the final image to a disc file,
to a formatted memory buffer, or to C-style memory array. See
[method@Image.write_to_file] and friends.

## Getting pixels

Use [class@Region] to read pixels out of images. You can use [func@IMAGE_ADDR]
as well, but this can need a large amount of memory to work. See [extending](
extending.html) for an introduction to writing your own operations.

## Error handling

libvips keeps a log of error message, see [func@error_buffer] and
[func@error_clear] to find out how to get and clear the error log.

## Example

On Unix systems, you can compile the [example code](#libvips-from-c-example)
with something like:

```bash
$ gcc -g -Wall myprog.c `pkg-config vips --cflags --libs`
```

On Windows, you'll need to set the compiler flags by hand, perhaps:

```bash
x86_64-w64-mingw32-gcc-win32 -mms-bitfields \
  -Ic:/vips-8.6/include \
  -Ic:/vips-8.6/include/glib-2.0 \
  -Ic:/vips-8.6/lib/glib-2.0/include \
  myprog.c \
  -Lc:/vips-8.6/lib \
  -lvips -lz -ljpeg -lstdc++ -lxml2 -lfftw3 -lm -lMagickWand -llcms2 \
  -lopenslide -lcfitsio -lpangoft2-1.0 -ltiff -lpng14 -lexif \
  -lMagickCore -lpango-1.0 -lfreetype -lfontconfig -lgobject-2.0 \
  -lgmodule-2.0 -lgthread-2.0 -lglib-2.0 -lintl \
  -o myprog.exe
```

## libvips from C example

```c
#include <stdio.h>
#include <vips/vips.h>

int
main(int argc, char **argv)
{
    VipsImage *in;
    double mean;
    VipsImage *out;

    if (VIPS_INIT(argv[0]))
        vips_error_exit(NULL);

    if (argc != 3)
        vips_error_exit("usage: %s infile outfile", argv[0]);

    if (!(in = vips_image_new_from_file(argv[1], NULL)))
        vips_error_exit(NULL);

    printf("image width = %d\n", vips_image_get_width(in));

    if (vips_avg(in, &mean, NULL))
        vips_error_exit(NULL);

    printf("mean pixel value = %g\n", mean);

    if (vips_invert(in, &out, NULL))
        vips_error_exit(NULL);

    g_object_unref(in);

    if (vips_image_write_to_file(out, argv[2], NULL))
        vips_error_exit(NULL);

    g_object_unref(out);

    return 0;
}
```

## Reference pools

libvips has a simple system to automate at least some reference counting
issues. Reference pools are arrays of object pointers which will be released
automatically when some other object is finalized.

The code below crops a many-page image (perhaps a GIF or PDF). It splits the
image into separate pages, crops each page, reassembles the cropped areas,
and saves again. It creates a `context` object representing the state of
processing, and `crop_animation` allocates two reference pools off that
using [method@Object.local_array], one to hold the cropped frames, and one
to assemble and copy the result.

All unreffing is handled by `main`, and it doesn't need to know anything
about `crop_animation`.

```c
#include <vips/vips.h>

static int
crop_animation(VipsObject *context, VipsImage *image, VipsImage **out,
    int left, int top, int width, int height)
{
    int page_height = vips_image_get_page_height(image);
    int n_pages = image->Ysize / page_height;
    VipsImage **page = (VipsImage **) vips_object_local_array(context, n_pages);
    VipsImage **copy = (VipsImage **) vips_object_local_array(context, 1);

    int i;

    /* Split the image into cropped frames.
     */
    for (i = 0; i < n_pages; i++)
        if (vips_crop(image, &page[i],
                left, page_height * i + top, width, height, NULL))
            return -1;

    /* Reassemble the frames and set the page height. You must copy before
     * modifying metadata.
     */
    if (vips_arrayjoin(page, &copy[0], n_pages, "across", 1, NULL) ||
        vips_copy(copy[0], out, NULL))
        return -1;
    vips_image_set_int(*out, "page-height", height);

    return 0;
}

int
main(int argc, char **argv)
{
    VipsImage *image;
    VipsObject *context;
    VipsImage *x;

    if (VIPS_INIT(NULL))
        vips_error_exit(NULL);

    if (!(image = vips_image_new_from_file(argv[1],
              "access", VIPS_ACCESS_SEQUENTIAL,
              NULL)))
        vips_error_exit(NULL);

    context = VIPS_OBJECT(vips_image_new());
    if (crop_animation(context, image, &x, 10, 10, 500, 500)) {
        g_object_unref(image);
        g_object_unref(context);
        vips_error_exit(NULL);
    }
    g_object_unref(image);
    g_object_unref(context);
    image = x;

    if (vips_image_write_to_file(image, argv[2], NULL)) {
        g_object_unref(image);
        vips_error_exit(NULL);
    }

    g_object_unref(image);

    return 0;
}
```
