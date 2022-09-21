Title: Using VIPS at the command-line

# Introduction

Use the <command>vips</command> command to execute VIPS operations from 
the command-line. For example:

```
$ vips rot k2.jpg x.jpg d90
```

Will rotate the image <literal>k2.jpg</literal> by 90 degrees 
anticlockwise and write the result to the file <literal>x.jpg</literal>. 
If you don't give any arguments to an operation, 
<command>vips</command> will give a short description, for example:

```
$ vips rot 
rotate an image
usage:
   rot in out angle
where:
   in           - Input image, input VipsImage
   out          - Output image, output VipsImage
   angle        - Angle to rotate image, input VipsAngle
                        default: d90
                        allowed: d0, d90, d180, d270
```

There's a straightforward relationship with the C API: compare this to 
the API docs for vips_rot().

# Listing all operations

You can list all classes with:

```
$ vips -l
... 
VipsOperation (operation), operations
  VipsSystem (system), run an external command
  VipsArithmetic (arithmetic), arithmetic operations
    VipsBinary (binary), binary operations
      VipsAdd (add), add two images
      ... etc.
```

Each line shows the canonical name of the class (for example 
<literal>VipsAdd</literal>), the class nickname 
(<literal>add</literal> in this case), and a short description. 
Some subclasses of operation will show more: for example, subclasses of 
<literal>VipsForeign</literal> will show some of the extra flags 
supported by the file load/save operations. 

The API docs have a <link linkend="function-list">handy table of all vips 
operations</link>, if you want to find out how to do something, try 
searching that. 

# Optional arguments

Many operations take optional arguments. You can supply these as 
command-line options. For example:

```
$ vips gamma
gamma an image
usage:
   gamma in out
where:
   in           - Input image, input VipsImage
   out          - Output image, output VipsImage
optional arguments:
   exponent     - Gamma factor, input gdouble
                  default: 2.4
                  min: 1e-06, max: 1000
operation flags: sequential-unbuffered 
```

vips_gamma() applies a gamma factor to an image. By 
default, it uses 2.4, the sRGB gamma factor, but you can specify any 
gamma with the <literal>exponent</literal> option. 

Use it from the command-line like this:

```
$ vips gamma k2.jpg x.jpg --exponent 0.42
```

This will read file <literal>k2.jpg</literal>, un-gamma it, and 
write the result to file <literal>x.jpg</literal>.

# Array arguments

Some operations take arrays of values as arguments. For example, 
vips_affine() needs an array of four numbers for the 
2x2 transform matrix. You pass arrays as space-separated lists:

```
$ vips affine k2.jpg x.jpg "2 0 0 1"
```

You may need the quotes to stop your shell breaking the argument at 
the spaces. vips_bandjoin() needs an array of input images to 
join, run it like this:

```
$ vips bandjoin "k2.jpg k4.jpg" x.tif
```

# Implicit file format conversion

<command>vips</command> will automatically convert between image file 
formats for you. Input images are detected by sniffing their first few 
bytes; output formats are set from the filename suffix. You can see a 
list of all the supported file formats with something like:

```
$ vips -l foreign
```

Then get a list of the options a format supports with:

```
$ vips jpegsave
```

You can pass options to the implicit load and save operations enclosed 
in square brackets after the filename:

```
$ vips affine k2.jpg x.jpg[Q=90,strip] "2 0 0 1"
```

Will write <literal>x.jpg</literal> at quality level 90 and will 
strip all metadata from the image.

# Chaining operations

Because each operation runs in a separate process, you can't use 
libvips's chaining system to join operations together, you have to use 
intermediate files. The command-line interface is therefore quite a bit 
slower than Python or C. 

The best alternative is to use vips files for intermediates. 
Something like:

```
$ vips invert input.jpg t1.v
$ vips affine t1.v output.jpg "2 0 0 1"
$ rm t1.v
```

# Other features

Finally, <command>vips</command> has a couple of useful extra options. 

- Use <option>--vips-progress</option> to get <command>vips</command>
  to display a simple progress indicator.

- Use <option>--vips-leak</option> and <command>vips</command> will leak-test
  on exit, and also display an estimate of peak memory use.

- Set <code>G_MESSAGES_DEBUG=VIPS</code> and GLib will display informational
  and debug messages from libvips.

VIPS comes with a couple of other useful programs. 
<command>vipsheader</command> is a command which can print image header
fields. <command>vipsedit</command> can change fields in vips format 
images. <command>vipsthumbnail</command> can make image thumbnails 
quickly. 
