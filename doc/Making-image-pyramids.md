  <refmeta>
    <refentrytitle>Image pyramids</refentrytitle>
    <manvolnum>3</manvolnum>
    <refmiscinfo>libvips</refmiscinfo>
  </refmeta>

  <refnamediv>
    <refname>Pyramids</refname>
    <refpurpose>How to use libvips to make image pyramids</refpurpose>
  </refnamediv>

libvips includes `vips_dzsave()`, an operation that can build image pyramids
compatible with [DeepZoom](http://en.wikipedia.org/wiki/Deep_Zoom), Zoomify
and [Google Maps](https://developers.google.com/maps/) image viewers. It's
fast and can generate pyramids for large images using only a small amount
of memory.

The TIFF writer, `vips_tiffsave()` can also build tiled pyramidal TIFF images,
but that's very simple to use. This page concentrates on the DeepZoom builder.  

Run dzsave with no arguments to see a summary:

```
$ vips dzsave
save image to deepzoom file
usage:
   dzsave in filename
where:
   in           - Image to save, input VipsImage
   filename     - Filename to save to, input gchararray
optional arguments:
   basename     - Base name to save to, input gchararray
   layout       - Directory layout, input VipsForeignDzLayout
			default: dz
			allowed: dz, zoomify, google
   suffix       - Filename suffix for tiles, input gchararray
   overlap      - Tile overlap in pixels, input gint
			default: 1
			min: 0, max: 8192
   tile-size    - Tile size in pixels, input gint
			default: 254
			min: 1, max: 8192
   centre       - Center image in tile, input gboolean
			default: false
   depth        - Pyramid depth, input VipsForeignDzDepth
			default: onepixel
			allowed: onepixel, onetile, one
   angle        - Rotate image during save, input VipsAngle
			default: d0
			allowed: d0, d90, d180, d270
   container    - Pyramid container type, input VipsForeignDzContainer
			default: fs
			allowed: fs, zip
   properties   - Write a properties file to the output directory, input
gboolean
			default: false
   compression  - ZIP deflate compression level, input gint
			default: 0
			min: -1, max: 9
   strip        - Strip all metadata from image, input gboolean
			default: false
   background   - Background value, input VipsArrayDouble
operation flags: sequential nocache 
```

You can also call `vips_dzsave()` from any language with a libvips binding, or
by using `.dz` or `.szi` as an output file suffix.

# Writing [DeepZoom](http://en.wikipedia.org/wiki/Deep_Zoom) pyramids

The `--layout` option sets the basic mode of operation. With no
`--layout`, dzsave writes DeepZoom pyramids. For example:

```
$ vips dzsave huge.tif mydz
```

This will create a directory called `mydz_files` containing the image
tiles, and write a file called `mydz.dzi` containing the image
metadata. 

You can use the `--suffix` option to control how tiles are written. For
example:

```
$ vips dzsave huge.tif mydz --suffix .jpg[Q=90]
```

will write JPEG tiles with the quality factor set to 90. You can set any
format write options you like, see the API docs for `vips_jpegsave()`
for details.

# Writing Zoomify pyramids

Use `--layout zoomify` to put dzsave into zoomify mode. For example:

```
$ vips dzsave huge.tif myzoom --layout zoomify
```

This will create a directory called `myzoom` containing a file called
`ImageProperties.xml` with the image metadata in, and a series of
directories called `TileGroupn`, each containing 256 image tiles.

As with DeepZoom, you can use `--suffix` to set jpeg quality.

# Writing [Google Maps](https://developers.google.com/maps/) pyramids

Use `--layout google` to write Google maps-style pyramids. These are
compatible with the [NYU Pathology pyramid
builder](http://code.google.com/p/virtualmicroscope/wiki/SlideTiler).
For example:

```
$ vips dzsave wtc.tif gmapdir --layout google
```

Will create a directory called `gmapdir` containing `blank.png`, the
file to display for blank tiles, and a set of numbered directories, one
for each zoom level. The pyramid can be sparse (blank tiles are not
written).

As with DeepZoom, you can use `--suffix` to set jpeg quality.

Use `--background` to set the background colour. This is the colour
displayed for bits of the pyramid not in the image (image edges, for
example). By default, the image background is white.

Use `--centre` to add a border to the image large enough to centre the
image within the lowest resolution tile. By default, images are not
centred.

For example:

```
$ vips dzsave wtc.tif gmapdir --layout google --background 0 --centre
```

# Other options

You can use `--tile-size` and `--overlap` to control how large the tiles
are and how they overlap (obviously). They default to the correct values
for the selected layout.

You can use `--depth` to control how deep the pyramid should be.  Possible
values are `onepixel`, `onetile` and `one`. `onepixel` means the image
is shrunk until it fits within a single pixel. `onetile` means shrink
until it fits with a tile. `one` means only write one pyramid layer (the
highest resolution one). It defaults to the correct value for the selected
layout. `--depth one` is handy for slicing up a large image into tiles
(rather than a pyramid).

You can use `--angle` to do a 90, 180 or 270 degree rotate of an image
during pyramid write.

You can use `--container` to set the container type. Normally dzsave will
write a tree of directories, but with `--container zip` you'll get a zip file
instead. Use .zip as the directory suffix to turn on zip format automatically:

```
$ vips dzsave wtc.tif mypyr.zip
```

to write a zipfile containing the tiles. You can use `.szi` as a suffix to
enable zip output as well. 

Use `--properties` to output an XML file called `vips-properties.xml`. This
contains a dump of all the metadata vips has about the image as a set of
name-value pairs. It's handy with openslide image sources. 

# Preprocessing images

You can use `.dz` as a filename suffix, meaning send the image to
`vips_dzsave()`. This means you can write the output of any vips operation to a
pyramid. For example:

```
$ vips extract_area huge.svs mypy.dz[layout=google] 100 100 10000 10000
```

The arguments to `extract_area` are image-in, image-out, left, top,
width, height. So this command will cut out a 10,000 by 10,000 pixel
area from near the top-left-hand corner of an Aperio slide image, then
build a pyramid in Google layout using just those pixels.

If you are working from OpenSlide images, you can use the shrink-on-load
feature of many of those formats. For example:

```
$ vips dzsave CMU-1.mrxs[level=1] x
```

Will pull out level 1 (the half-resolution level of an MRXS slide) and
make a pyramid from that.

# Troubleshooting

If you are building vips from source you do need to check the summary at
the end of configure carefully. You must have the `libgsf-1-dev` package
for `vips_dzsave()` to work.


