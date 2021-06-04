### Introduction

The libvips C++ API is a thin layer over the libvips GObject API. It adds
automatic reference counting, exceptions, operator overloads, and automatic
constant expansion.

You can drop down to the C API at any point, so all the C API docs also
work for C++.

### Example

    /* compile with:
     *      g++ -g -Wall example.cc `pkg-config vips-cpp --cflags --libs`
     */

    #include <vips/vips8>

    using namespace vips;

    int
    main (int argc, char **argv)
    { 
      if (VIPS_INIT (argv[0])) 
        vips_error_exit (NULL);
      
      if (argc != 3)
        vips_error_exit ("usage: %s input-file output-file", argv[0]);

      VImage in = VImage::new_from_file (argv[1],
        VImage::option ()->set ("access", VIPS_ACCESS_SEQUENTIAL));
      
      double avg = in.avg ();
      
      printf ("avg = %g\n", avg);
      printf ("width = %d\n", in.width ());
      
      in = VImage::new_from_file (argv[1],
        VImage::option ()->set ("access", VIPS_ACCESS_SEQUENTIAL));
      
      VImage out = in.embed (10, 10, 1000, 1000,
        VImage::option ()->
          set ("extend", "background")->
          set ("background", 128));
      
      out.write_to_file (argv[2]);
      
      vips_shutdown ();
      
      return 0;
    }

Everything before `VImage in = VImage::new_from_file()` is exactly as the C
API. `vips_error_exit()` just prints the arguments plus the libvips error
log and exits with an error code.

`VImage::new_from_file()` is the C++ equivalent of
`vips_image_new_from_file()`. It works in the same way, the differences being:

- VImage lifetime is managed automatically, like a smart pointer. You don't 
  need to call `g_object_unref()`. 

- Instead of using varargs and a `NULL`-terminated option list, this
  function takes an optional `VOption` pointer. This gives a list of name /
  value pairs for optional arguments to the function.

  In this case we request unbuffered IO for the image, meaning, we expect
  to do a single top-to-bottom scan of the image and do not need it to be
  decompressed entirely. You can use the C enum name, as is done in this
  case, or use a string and have the string looked up. See below.

  The function will delete the `VOption` pointer for us when
  it's finished with it.

- Instead of returning `NULL` on error, this constructor will raise a `VError`
  exception.

There are a series of similar constructors which parallel the
other constructors in the C API, see `VImage::new_from_memory()`,
`VImage::new_from_buffer()`, and `VImage::new_matrix()`.

The convenience function `VImage::new_from_image()` makes a constant image
from an existing image. The image it returns will have the same size,
interpretation, resolution and format as the image you call it on, but with
every pixel having the constant value you specify. For example:

      new_image = image.new_from_image (12);

Now `new_image` has the same size as `image`, but has one band, and every
pixel has the value 12. You can pass a `std::vector<double>` as the
argument to make a constant image with a different number of bands.

There's also `VImage::new_memory()` and `VImage::new_temp_file()`, which when
written to with `VImage::write()` will create whole images on memory or on disc.

The next line finds the average pixel value, it's the equivalent of the 
`vips_avg()` function. The differences from the C API are:

- `VImage::avg()` is a member function: the `this` 
  parameter is the first (the only, in this case) input image. 

- The function returns the first output parameter, in this case the
  average pixel value. Other return values are via pointer arguments,
  as in the C API.

- Like `VImage::new_from_file()`, function raises the `VError`
  exception on error.

- Like `VImage::new_from_file()`, extra arguments are passed 
  via an optional `VOption` parameter. There are none
  in this case, so the function brackets can be left empty.

All other operations follow the same pattern, for example the C API call 
`vips_add(`):

    int vips_add (VipsImage *left, VipsImage *right, VipsImage **out, ...);

appears in C++ as:

    VImage VImage::add (VImage right, VOption *options) const

The next line uses `VImage::width()` to get the image width in pixels.
There are similar functions paralleling `vips_image_get_format()` and
friends. Use `VImage::set()` to set metadata fields, `VImage::get_int()` and
c. to fetch metadata.

Next we reload the image. The `VImage::avg()` will have scanned the image 
and reached the end of the file, we need to scan again for the next 
operation. If we'd selected random access mode (the default) in the 
original `VImage::new_from_file()`, we would not need to reload.

The next line runs `vips_embed()` with two optional parameters. The first
sets the value to an enum (here we use a string to set the value, it'll be
looked up in the list of possible enum values, or you can use the symbols
from the C API), the second sets the value to an `int`. The `"background"`
parameter is actually a `VipsArrayDouble`: if you pass an `int` instead,
it will be automatically converted to a one-element array for you. You can
pass a `std::vector<double>` too: the utility function `VImage::to_vectorv()`
is a convenient way to make one.

Finally, `VImage::write_to_file()` will write the new image to the
filesystem. You can add a `VOption` as a final parameter and set options for
the writer if you wish. Again, the operation will throw a `VError` exception
on error. The other writers from the C API are also present: you can write
to a memory array, to a formatted image in memory, or to another image.

The API docs have a [handy table of all vips
operations](libvips/API/current/func-list.html), if you want to find out
how to do something, try searching that.

### Automatic constant expansion

The C++ API will automatically turn constants into images in some cases. 
For example, you can join two images together bandwise (the 
bandwise join of two RGB images would be a six-band image) with:

    VImage rgb = ...; 
    VImage six_band = rgb.bandjoin (rgb);

You can also bandjoin a constant, for example: 

    VImage rgb_with_alpha = rgb.bandjoin (255);

Will add an extra band to an image, with every element in the new band having
the value 255. This is quite a general feature. You can use a constant in
most places where you can use an image and it will be converted. For example:

    VImage a = (a < 128).ifthenelse (128, a); 

Will set every band element of `a` less than 128 to 128. 

The C++ API includes the usual range of arithmetic operator overloads. 
You can mix constants, vectors and images freely.

The API overloads `[]` to be `vips_extract_band()`. You can 
write:

    VImage xyz = VImage::xyz (256, 256) - VImage::to_vectorv (2, 128.0, 128.0); 
    VImage mask = (xyz[0].pow (2) + xyz[1].pow (2)).pow (0.5) < 100;

to make a circular mask, for example.

The API overloads `()` to be `vips_getpoint()`. You can write:

    VImage xyz = VImage::xyz (256, 256) - VImage::to_vectorv (2, 128.0, 128.0); 
    // this will have the value [0, 0]
    std::vector<double> point = xyz (128, 128);

### Enum expansion

libvips operations which implement several functions with a controlling 
enum, such as `vips_math()`, are expanded to a set of member functions 
named after the enum. For example, the C function:

    int vips_math (VipsImage *in, VipsImage **out, VipsOperationMath math, ...);

where `VipsOperationMath` has the member `VIPS_OPERATION_MATH_SIN`, has a 
C convenience function `vips_sin()`:

    int vips_sin (VipsImage *in, VipsImage **out, ...);

and a C++ member function `VImage::sin()`:

    VImage VImage::sin (VOption *options = 0) const

### Image metadata

libvips images can have a lot of metadata attached to them, giving things like
ICC profiles, EXIF data, and so on. You can use the command-line program
`vipsheader` with the `-a` flag to list all the fields.

You can read metadata items with the member functions `get_int()`,
`get_double()`, `get_string()` and `get_blob()`. Use `get_typeof()` to call
`vips_image_get_typeof()` and read the type of an item. This will return 0
for undefined fields.

    const char *VImage::get_string (const char *field);

You can use the `set()` family of overloaded members to set metadata,
for example:

    void VImage::set (const char *field, const char *value);

You can use these functions to manipulate exif metadata, for example:

    VImage im = VImage::new_from_file ("x.jpg")
    int orientation = im.get_int (VIPS_META_ORIENTATION);
    im.set (VIPS_META_ORIENTATION, 2);
    im.write_to_file ("y.jpg");

### Extending the C++ interface

The C++ interface comes in two parts. First, `VImage8.h` defines a simple
layer over `GObject` for automatic reference counting, then a generic way
to call any vips8 operation with `VImage::call()`, then a few convenience
functions, then a set of overloads.

The member definition and declaration for each operation, for
example `VImage::add()`, is generated by a small Python program called
`gen-operators.py`. If you write a new libvips operator, you'll need to rerun
this program to make it visible in the C++ interface.

You can write the wrapper yourself, of course, they are very simple.
The one for `VImage::add()` looks like this:

    VImage VImage::add (VImage right, VOption *options) const
    {
        VImage out;

        call("add",
            (options ? options : VImage::option())->
                set("out", &amp;out)->
                set("left", *this)->
                set("right", right));

        return out;
    }

Where `VImage::call()` is the generic call-a-vips8-operation function.
