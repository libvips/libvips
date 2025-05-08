Title: Advanced > Writing operators

This section runs quickly through adding a simple operator to libvips.
For more information, see [class@Operation] and [class@Region]. A good
starting point for a new operation is a similar one in libvips.

All libvips operations are subclasses of [class@Operation], which in turn
subclasses [class@Object] and then [class@GObject.Object]. You add an
operation to libvips by defining a new subclass of [class@Operation] and
arranging for its `class_init()` to be called, perhaps by calling its
`get_type()` function.

## The class and object structures

First you need to define a new object struct and a new class struct.

```c
typedef struct _Negative {
  VipsOperation parent_instance;

  VipsImage *in;
  VipsImage *out;

  int image_max;

} Negative;

typedef struct _NegativeClass {
  VipsOperationClass parent_class;

  /* No new class members needed for this op.
   */

} NegativeClass;
```

This operation will find the photographic negative of an unsigned 8-bit
image, optionally letting you specify the value which the pixels "pivot"
about. It doesn't need any class members (ie. values common to all operations
of this type), so the second struct is empty. See the source to
[method@Image.invert] for a more complete version of this operation that's
actually in the library.

[class@GObject.Object] has a handy macro to write some of the boilerplate for
you.

```c
G_DEFINE_TYPE(Negative, negative, VIPS_TYPE_OPERATION);
```

[func@GObject.DEFINE_TYPE] defines a function called `negative_get_type()`,
which registers this new class and returns its [alias@GObject.Type] (a
pointer-sized integer). `negative_get_type()` in turn needs two functions,
`negative_init()`, to initialise a new instance, and `negative_class_init()`,
to initialise a new class.

## Class and object initialisation

`negative_init()` is very simple, it just sets the default value for our
optional parameter.

```c
static void
negative_init(Negative *negative)
{
  negative->image_max = 255;
}
```

`negative_class_init()` is more complicated: it has to set various fields in
various superclasses and define the operation's parameters.

```c
static void
negative_class_init(NegativeClass *class)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS(class);
    VipsObjectClass *object_class = VIPS_OBJECT_CLASS(class);

    gobject_class->set_property = vips_object_set_property;
    gobject_class->get_property = vips_object_get_property;

    object_class->nickname = "negative";
    object_class->description = "photographic negative";
    object_class->build = negative_build;

    VIPS_ARG_IMAGE(class, "in", 1,
        "Input",
        "Input image",
        VIPS_ARGUMENT_REQUIRED_INPUT,
        G_STRUCT_OFFSET(Negative, in));

    VIPS_ARG_IMAGE(class, "out", 2,
        "Output",
        "Output image",
        VIPS_ARGUMENT_REQUIRED_OUTPUT,
        G_STRUCT_OFFSET(Negative, out));

    VIPS_ARG_INT(class, "image_max", 4,
        "Image maximum",
        "Maximum value in image: pivot about this",
        VIPS_ARGUMENT_OPTIONAL_INPUT,
        G_STRUCT_OFFSET(Negative, image_max),
        0, 255, 255);
}
```

In [class@GObject.Object], it needs to set the getters and setters for this
class. libvips has a generic get/set system, so any subclass of
[class@VipsObject] needs to use the libvips ones.

In [class@VipsObject], it needs to set the operation
[property@VipsObject:nickname] and [property@VipsObject:description], and set
a build function (see below). [property@VipsObject:nickname] is used to refer
to this operation in the API, [property@VipsObject:description] is used to
explain this operation to users and will be translated into their language.

Finally, it needs to define the arguments the constructor for this class
takes. There are a set of handy macros for doing this, see [func@ARG_INT]
and friends.

The first few parameters are always the same and mean: class pointer for
argument, argument name, argument priority (bindings expect required arguments
in order of priority), long argument name (this one is internationalised
and displayed to users), description (again, users can see this), some flags
describing the argument, and finally the position of the member in the struct.

Integer arguments take three more values: the minimum, maximum and
default value for the argument.

## The `build()` function

The build function is the thing [class@VipsObject] calls during object construction,
after all arguments have been supplied and before the object is used. It
has two roles: to verify that arguments are correct, and then to construct
the object.  After `build()`, the object is expected to be ready for use.

```c
static int
negative_build(VipsObject *object)
{
    VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
    Negative *negative = (Negative *) object;

    if (VIPS_OBJECT_CLASS(negative_parent_class)->build(object))
        return -1;

    if (vips_check_uncoded(class->nickname, negative->in) ||
        vips_check_format(class->nickname, negative->in, VIPS_FORMAT_UCHAR))
        return -1;

    g_object_set(object, "out", vips_image_new(), NULL);

    if (vips_image_pipelinev(negative->out,
            VIPS_DEMAND_STYLE_THINSTRIP, negative->in, NULL))
        return -1;

    if (vips_image_generate(negative->out,
            vips_start_one,
            negative_generate,
            vips_stop_one,
            negative->in, negative))
        return -1;

    return 0;
}
```

`negative_build()` first chains up to the superclass: this will check that
all input arguments have been supplied and are sane.

Next, it adds its own checks. This is a demo operation, so we just work for
uncoded, unsigned 8-bit images. There are a lot of convenience functions
like [func@check_format], see the docs.

Next, it creates the output image. This needs to be set with [method@Object.set]
so that libvips can see that it has been assigned. libvips will also handle the
reference counting for you.

[method@Image.pipelinev] links our new image onto the input image and notes
that this operation prefers to work in lines. You can request other input
geometries, see [enum@DemandStyle].

The geometry hint is just a hint, an operation needs to be able to supply any
size [class@Region] on request. If you must have a certain size request, you
can put a cache in the pipeline after your operation, see
[method@Image.linecache] and [method@Image.tilecache]. You can also make requests
to your operation ordered, see [method@Image.sequential].

Finally, [method@Image.generate] attaches a set of callbacks to the output
image to generate chunks of it on request. [func@start_one] and [func@stop_one]
are convenience functions that make the input region for you, see below.

## The `generate()` function

The `generate()` function does the actual image processing. `negative_generate()`
(of type [callback@GenerateFn], supplied to [method@Image.generate] above) is
called  whenever some pixels of our output image are required.

```c
static int
negative_generate(VipsRegion *out_region,
    void *vseq, void *a, void *b, gboolean *stop)
{
    /* The area of the output region we have been asked to make.
     */
    VipsRect *r = &out_region->valid;

    /* The sequence value ... the thing returned by vips_start_one().
     */
    VipsRegion *ir = (VipsRegion *) vseq;

    VipsImage *in = (VipsImage *) a;
    Negative *negative = (Negative *) b;
    int line_size = r->width * negative->in->Bands;

    int x, y;

    /* Request matching part of input region.
     */
    if (vips_region_prepare(ir, r))
        return -1;

    for (y = 0; y < r->height; y++) {
        unsigned char *p = (unsigned char *)
            VIPS_REGION_ADDR(ir, r->left, r->top + y);
        unsigned char *q = (unsigned char *)
            VIPS_REGION_ADDR(out_region, r->left, r->top + y);

        for (x = 0; x < line_size; x++)
            q[x] = negative->image_max - p[x];
    }

    return 0;
}
```

This has to calculate a section of the output image. The output
[class@Region], `out_region`, contains a [struct@Rect] called `valid`
which is the area needing calculation. This call to `negative_generate()`
must somehow make this part of `out_region` contain pixel data.

`vseq` is the sequence value. This is the per-thread state for this generate,
created (in this example) by [func@start_one]. In this simple case it's
just a [class@Region] defined on the input image. If you need more per-thread
state you can write your own start and stop functions and have a struct
you create and pass as a sequence value. There are plenty of examples in
the libvips source code, see [method@Image.rank].

`a` and `b` are the last two arguments to [method@Image.generate] above.
`stop` is a bool pointer you can set to stop computation early.
[method@Image.min] on an unsigned int image, for example, will set `stop`
as soon as it sees a zero, and will not scan the entire image.

The first thing `negative_generate()` does is use [method@Region.prepare] to
ask for the corresponding pixels from the input image. Operations which do
coordinate transforms or which need an area of input for each output point
will need to calculate a new rect before calling [method@Region.prepare].

Finally, it can calculate some pixels. `negative_generate()` loops over the
valid area of the output and calls [func@REGION_ADDR] for each line. This
macro is reasonably quick, but it's best not to call it for each pixel. Once
per line is fine though.

## Adding to libvips

To add the operation to libvips, just call `negative_get_type()`. You can
include the source in your program, or use [GModule](
https://docs.gtk.org/gmodule/) to make a binary plugin that will be loaded
by libvips at startup. There are some [example plugins available](
https://github.com/jcupitt/vips-gmic).

You can then use `negative` from any of the libvips interfaces. For example,
in Python you'd use it like this:

```python
out = in.negative(image_max=128)
```

From the command-line it'd look like this:

```bash
$ vips negative in.png out.tif --image-max 128
```

And from C like this:

```c
VipsImage *in;
VipsImage *out;
if (vips_call("negative", in, &out, "image_max", 128, NULL))
    ... error
```

Unfortunately that will do almost no compile-time type checking, so all
libvips operations have a tiny extra wrapper to add a bit of safety. For
example:

```c
static int
negative(VipsImage *in, VipsImage **out, ...)
{
    va_list ap;
    int result;

    va_start(ap, out);
    result = vips_call_split("negative", ap, in, out);
    va_end(ap);

    return result;
}
```

And now you can write:

```c
if (negative(in, &out, "image_max", 128, NULL))
    ... error
```

and it's at least a bit safer.

## Other types of operation

Change the `_build()` function to make other types of operation.

Use [method@Image.generate] with [func@start_many] to make operations which
demand pixels from more than one image at once, such as image plus image.

Use [method@Image.sink] instead of [method@Image.generate] to loop over an
image and calculate a value. libvips uses this for the statistics operations,
like [method@Image.avg].

Use [method@Image.wio_input] to get an entire image into memory so you can
read it with a pointer. This will obviously not scale well to very large
images, but some operations, like FFTs or flood-fill, need the whole image
to be available at once.

Make area operations, like filters, by enlarging the [struct@Rect] that
`_generate()` is given before calling [method@Region.prepare]. You can enlarge
the input image, so that the output image is the same size as the original
input, by using [method@Image.embed] within the `_build()` function.

Make things like flips and rotates by making larger changes to the [struct@Rect]
in `_generate()`.

Make zero-copy operations, like [method@Image.insert], with
[method@Region.region].
