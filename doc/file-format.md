Title: Technical background > The libvips file format

libvips has a simple, native file format. It's very fast, there is no image
size limit, and it supports arbitrary metadata. Although few other programs
can read these images (though recent versions of ImageMagick do have basic
support for the `.v` format), it can be useful as an intermediate format
for command-line processing. For example:

```bash
$ vips invert input.tif t.v
$ vips gamma t.v output.tif
```

is faster than using `.tif` for the temporary intermediate image. This
section documents the libvips file format.

libvips comes with a command-line program called `vipsedit` which is useful
for destructively changing fields in a `.v` image. The `vipsheader` program
can be used to extract any metadata.

libvips files come in three parts. First, there is a 64-byte header, containing
an identifying magic number and a set of very basic fields, such as image
width in pixels. Next, the image data is stored as a set of band-interleaved
scanlines, from the top of the image to the bottom. Finally, after the
pixel data comes an optional block of XML containing any extra metadata,
such as an ICC profile or the EXIF data.

## The header

The fields in the libvips header are always stored least-significant byte first
(Intel ordering). Only the most basic information about the image is in
the header: most metadata is stored in the XML extension block after the
pixel data.

If the first four bytes of the file are in order 08 f2 a6 b6, the image
data (see the next section) is stored in Intel byte order (LSB first)
and will need to be swapped if read on a SPARC-style machine (MSB first).
If the magic number is b6 a6 f2 08, the image data is in SPARC order and
will need to swapped if read on an Intel-style machine. libvips does this
swapping automatically.

| Bytes   | Type                  | libvips name     | Meaning                                   |
|---------|-----------------------|------------------|-------------------------------------------|
| 0 - 3   |                       |                  | Magic number: 08 f2 a6 b6, or b6 a6 f2 08 |
| 4 - 7   | int32                 | `width`          | Width of image, in pixels                 |
| 8 - 11  | int32                 | `height`         | Height of image, in pixels                |
| 12 - 15 | int32                 | `bands`          | Number of image bands (channels)          |
| 16 - 19 |                       |                  | Unused                                    |
| 20 - 23 | [enum@BandFormat]     | `format`         | Band format                               |
| 24 - 27 | [enum@Coding]         | `coding`         | Image coding                              |
| 28 - 31 | [enum@Interpretation] | `interpretation` | Pixel interpretation                      |
| 32 - 35 | float32               | `xres`           | Horizontal resolution, in pixels per mm   |
| 36 - 39 | float32               | `yres`           | Vertical resolution, in pixels per mm     |
| 40 - 47 |                       |                  | Unused                                    |
| 48 - 51 | int32                 | `xoffset`        | Horizontal offset of origin, in pixels    |
| 52 - 55 | int32                 | `yoffset`        | Vertical offset of origin, in pixels      |
| 56 - 63 |                       |                  | Unused                                    |

## The image data

If `coding` is set to [enum@Vips.Coding.NONE], pixels are stored in native C
format, that is, the native format of the machine that wrote the data. If you
open a big-endian image on a little-endian machine, libvips will automatically
byte-swap for you.  libvips has 10 band formats, see [enum@BandFormat].
Image data is stored as a simple list of scanlines, from the top of the
image to the bottom. Pixels are band-interleaved, so RGBRGBRGBRGB, for
example. There is no padding at the end of scanlines.

If `coding` is set to [enum@Vips.Coding.LABQ], each pixel is four bytes, with
10 bits for L\* and 11 bits for each of a\* and b\*. These 32 bits are packed
into 4 bytes, with the most significant 8 bits of each value in the first
3 bytes, and the left-over bits packed into the final byte as 2:3:3.

If `coding` is set to [enum@Vips.Coding.RAD], each pixel is RGB or XYZ float,
with 8 bits of mantissa and then 8 bits of exponent, shared between the
three channels. This coding style is used by the Radiance family of programs
(and the HDR format) commonly used for HDR imaging.

Other values of `coding` can set other coding styles. Use
[func@IMAGE_SIZEOF_IMAGE] to calculate the size of the image data section.

## The metadata

Following the image data is a chunk of XML holding a simple list of name-value
pairs. Binary data is encoded with base64. Use [method@Image.set] and friends
to set and get image metadata.

You can use `vipsheader -f getext some_file.v` to get the XML from a libvips
image, and `vipsedit --setext some_file.v < file.xml` to replace the XML.
