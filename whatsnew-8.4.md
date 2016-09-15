libvips 8.4 should be out by the end of September 2016. This page introduces the main features. 

## New operators

There are some fun new operators. `vips_perlin()` and `vips_worley()`
make Perlin and Worley noise. They are useful for generating
synthetic random textures. The implementations in vips can generate images of
any size very quickly. 

Here's an example of a marble texture simulated with a Perlin noise generator
using the Ruby libvips binding. 

```
#!/usr/bin/ruby

require 'vips'

size = 1024

# perlin's "turbulence" image
def turbulence(size)
    layers = []
    iterations = Math.log(size, 2) - 2
    (0 ... iterations).each do |i|
        layer = Vips::Image.perlin(size, size, :cell_size => size / 2 ** i)
        layer = layer.abs * (1.0 / (i + 1))
        layers << layer
    end

    layers.reduce(:+) 
end

# make a 256 element colour map: a linear fade from start to stop, with 
# start and stop as CIELAB colours, the output map as sRGB
def gradient(start, stop)
    lut = Vips::Image.identity / 255
    lut = lut * start + (lut * -1 + 1) * stop
    lut.colourspace(:srgb, :source_space => :lab)
end

# an image where the pixel value is 0 .. 4 * 360 across 
angles = Vips::Image.xyz(size, size)[0] * 360 * 4 / size 

# make a turbulent stripe pattern using 0 .. 255
stripe = ((angles + turbulence(size) * 700).sin + 1) * 128

# make a colour map (a smooth gradient from white to dark brown) then map 
# our turbulent image through it
dark_brown = [7.45, 4.3, 8]
white = [100, 0, 0]
stripe = stripe.maplut(gradient(dark_brown, white))

stripe.write_to_file ARGV[0]
```

## Rewritten convolution

The convolution functions were the old vips7 ones with a small
wrapper. They've now been rewritten for vips8, and the vector path has
been completely replaced. It can be up to about 2x faster.

The old vips7 vector path was based on int arithmetic, so this mask
(a simple 3x3 average), for example:

```
3 3 9 0
1 1 1
1 1 1
1 1 1
```

Would be computed as nine adds, followed by a divide by the constant 9,
with round-to-nearest. This was obviously accurate, but dividing
by a constant is slow.

The new path first computes a fixed-point float approximation of the
int mask. In this case it'll settle on this:

```
3 3 1 0
3 3 3 
3 4 4 
4 4 4 
```

Where 3 is approximately 1/9 in 3.5 bit fixed-point, and the whole
mask sums to 1.0 (the sum of the int mask), or 32 in 3.5 bit. 

It's not possible to match each element and the sum at the same time,
so vips uses an iterative algorithm to find the approximation that
matches the sum exactly, matches each element as well as it can, and
which spreads any error through the mask. In this case, the mix of 3 and 4
is there to make the sum work. There's an error test and a fallback:
if the maximum possible error is over 10%, it'll switch to a non-vector
path based on exact int arithmetic. You can use `--vips-info` to see
what path ends up being taken.

Now there's a fixed-point version of the mask, vips can compute the
convolution as 9 fused multiply-adds, followed by an add and a 5-bit shift
to get back to the nearest int. Getting rid of the divide-by-a-constant
gives a nice speed improvement. On my laptop with vips 8.3 and a 10k x 10k
pixel RGB image I see:

```
$ time vips conv wtc.v x7.v avg.mat --vips-info
real	0m1.311s
user	0m1.376s
sys	0m0.372s
```

With vips 8.4 it's now:

```
$ time vips convi wtc.v x8.v avg.mat --vips-info
info: convi: using vector path
real	0m0.774s
user	0m0.888s
sys	0m0.352s

```

The peak error is small:

```
$ vips subtract x7.v x8.v x.v
$ vips abs x.v x2.v
$ vips max x2.v
11.000000
```

## Image resize

`vips_resize()` has seen some good improvements. 

* There's a new `centre` option which switches over to centre-convention for
  subsampling. This makes it a much better match for ImageMagick.
  `vipsthumbnail` uses this new option. 
* It now does round-to-nearest when calculating image bounds. This makes it
  much simpler to calculate a shrink factor which will produce an image of a
  specific size.
* A series of changes improve accuracy for the linear and cubic kernels, and
  improve spatial accuracy.
* It used to simply use nearest for upsampling, in line with things like PDF,
  but this is not a good choice for many applications. It now upsizes with
  bicubic by default. 

## Unicode on Windows

This is only a small thing, but the Windows build now supports Unicode
filenames. 

## File format support

As usual, there are a lot of improvements to file format read and write. 

* Thanks to work by Felix Bünemann, `webp` read and write supports many more 
  options.
* andris has improved `pdfload` so you can load many pages in a single 
  operation.
* Many people have worked on `dzsave` Google mode. It's now better at 
  skipping blank tiles and supports tile overlaps. Felix Bünemann added 
  support for compressed zip output. 
* Henri Chain has added `radsave_buffer` to improve Radiance support.
* TIFF files with an orientation tag should now autorotate, `tiffsave` 
  has better jpeg compression support, and it knows about the `strip` 
  metadata option.
* The load-via-libMagick operator now supports IM7.
* The GIF loader is much smarter about guessing the number of colour channels.
* PNG save supports `strip`.
* The SVG loader supports `svgz` compressed files thanks to Felix Bünemann.

## Other

Improvements to the build system, reductions in memory use, many small
bug fixes, improvements to the C++ binding, improvements to the Python binding, 
many small performance fixes. As usual, the ChanegLog has more detail if 
you're interested.
