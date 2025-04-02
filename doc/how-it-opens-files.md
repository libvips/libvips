Title: How libvips opens files

# How libvips opens files

libvips has at least four different ways of opening image files, each
best for different file types, file sizes and image use cases. libvips tries
hard to pick the best strategy in each case and mostly you don't need to
know what it is doing behind the scenes, except unfortunately when you do.

This page tries to explain what the different strategies are and when each is
used. If you are running into unexpected memory, disc or CPU use, this might
be helpful. [ctor@Image.new_from_file] has the official documentation.

## Caching

libvips caches recent operations. This means that if a file changes between
one load and the next, the second load will return the old image, even though
the file has been replaced.

You can force libvips to load a file and ignore any cached value by
setting the `revalidate` flag, see [class@ForeignLoad].

## Direct access

This is the fastest and simplest one. The file is mapped directly into the
process's address space and can be read with ordinary pointer access. Small
files are completely mapped; large files are mapped in a series of small
windows that are shared and which scroll about as pixels are read. Files
which are accessed like this can be read by many threads at once, making
them especially quick. They also interact well with the computer's operating
system: your OS will use spare memory to cache recently used chunks of the
file.

For this to be possible, the file format needs to be a simple dump of a memory
array. libvips supports direct access for `.v`, 8-bit binary ppm/pbm/pnm,
analyse and raw.

libvips has a special direct write mode where pixels can be written directly
to the file image. This is used for the [draw operations](libvips-draw.html).

## Random access via load library

Some image file formats have libraries which allow true random access to
image pixels. For example, libtiff lets you read any tile out of a tiled
tiff image very quickly. Because the libraries allow true random access,
libvips can simply hook the image load library up to the input of the
operation pipeline.

These libraries are generally single-threaded, so only one thread may
read at once, making them slower than simple direct access.
Additionally, tiles are often compressed, meaning that each time a tile
is fetched it must be decompressed. libvips keeps a cache of
recently-decompressed tiles to try to avoid repeatedly decompressing the
same tile.

libvips can load tiled tiff, tiled OpenEXR, FITS and OpenSlide images in
this manner.

## Full decompression

Many image load libraries do not support random access. In order to use
images of this type as inputs to pipelines, libvips has to convert them
to a random access format first.

For small images (less than 100mb when decompressed), libvips allocates
a large area of memory and decompresses the entire image to that. It
then uses that memory buffer of decompressed pixels to feed the
pipeline. For large images, libvips decompresses to a temporary file on
disc, then loads that temporary file in direct access mode (see above).
Note that on open libvips just reads the image header and is quick: the
image decompress happens on the first pixel access.

You can control this process with environment variables, command-line
flags and API calls as you choose, see [ctor@Image.new_from_file].
They let you set the threshold at which libvips switches between memory
and disc and where on disc the temporary files are held.

This is the slowest and most memory-hungry way to read files, but it's
unavoidable for many file formats. Unless you can use the next one!

## Sequential access

This a fairly recent addition to libvips and is a hybrid of the previous
two.

Imagine how this command might be executed:

```bash
$ vips flip fred.jpg jim.jpg vertical
```

meaning, read `fred.jpg`, flip it up-down, and write as `jim.jpg`.

In order to write `jim.jpg` top-to-bottom, it'll have to read `fred.jpg`
bottom-to-top. Unfortunately libjpeg only supports top-to-bottom reading
and writing, so libvips must convert `fred.jpg` to a random access format
before it can run the flip operation.

However many useful operations do not require true random access. For
example:

```bash
$ vips shrink fred.png jim.png 10 10
```

meaning shrink `fred.png` by a factor of 10 in both axes and write as
`jim.png`.

You can imagine this operation running without needing `fred.png` to be
completely decompressed first. You just read 10 lines from `fred.png` for
every one line you write to `jim.png`.

To help in this case, libvips has a hint you can give to loaders to say
"I will only need pixels from this image in top-to-bottom order". With
this hint set, libvips will hook up the pipeline of operations directly
to the read-a-line interface provided by the image library, and add a
small cache of the most recent 100 or so lines.

This is done automatically in command-line operation. In programs, you need to
set `access` to #VIPS_ACCESS_SEQUENTIAL in calls to functions like
[ctor@Image.new_from_file].
