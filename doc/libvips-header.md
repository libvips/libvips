Title: Operator index > By section > Header

<!-- libvips/iofuncs/header.c -->

libvips supports getting and setting image header data (including metadata)
in a uniform way.

Use [method@Image.get_typeof] to test for the existence and
[alias@GObject.Type] of a header field.

You can attach arbitrary metadata to images. Metadata is copied as images
are processed, so all images which used this image as input, directly or
indirectly, will have this same bit of metadata attached to them. Copying
is implemented with reference-counted pointers, so it is efficient, even for
large items of data. This does however mean that metadata items need to be
immutable. Metadata is handy for things like ICC profiles or EXIF data.

Various convenience functions (e.g. [method@Image.set_int]) let you easily
attach simple types like numbers, strings and memory blocks to images.
Use [method@Image.map] to loop over an image's fields, including all metadata.

Items of metadata are identified by strings. Some strings are reserved, for
example the ICC profile for an image is known by convention as
"icc-profile-data" (i.e. the [const@META_ICC_NAME] constant).

If you save an image in `.v` format, all metadata (with a restriction, see
below) is automatically saved for you in a block of XML at the end of the
file. When you load a `.v` image, the metadata is restored. You can use the
`vipsedit` command-line tool to extract or replace this block of XML.

`.v` metadata is based on [struct@GObject.Value]. See the docs for that
system if you want to do fancy stuff such as defining a new metadata type.
libvips defines a new [struct@GObject.Value] called [struct@SaveString], a
variety of string, see [func@value_set_save_string]. If your
[struct@GObject.Value] can be transformed to [struct@SaveString], it will
be saved and loaded to and from `.v` files for you.

libvips provides a couple of base classes which implement reference-counted
areas of memory. If you base your metadata on one of these types, it can be
copied between images efficiently.

## Callbacks

* [callback@ImageMapFn]

## Functions

* [func@format_sizeof]
* [func@format_sizeof_unsafe]
* [func@Interpretation.max_alpha]
* [method@Image.get_width]
* [method@Image.get_height]
* [method@Image.get_bands]
* [method@Image.get_format]
* [func@Image.get_format_max]
* [method@Image.guess_format]
* [method@Image.get_coding]
* [method@Image.get_interpretation]
* [method@Image.guess_interpretation]
* [method@Image.get_xres]
* [method@Image.get_yres]
* [method@Image.get_xoffset]
* [method@Image.get_yoffset]
* [method@Image.get_filename]
* [method@Image.get_mode]
* [method@Image.get_scale]
* [method@Image.get_offset]
* [method@Image.get_page_height]
* [method@Image.get_n_pages]
* [method@Image.get_n_subifds]
* [method@Image.get_orientation]
* [method@Image.get_orientation_swap]
* [method@Image.get_concurrency]
* [method@Image.get_data]
* [method@Image.init_fields]
* [method@Image.set]
* [method@Image.get]
* [method@Image.get_as_string]
* [method@Image.get_typeof]
* [method@Image.remove]
* [method@Image.map]
* [method@Image.get_fields]
* [method@Image.set_area]
* [method@Image.get_area]
* [method@Image.set_blob]
* [method@Image.set_blob_copy]
* [method@Image.get_blob]
* [method@Image.get_int]
* [method@Image.set_int]
* [method@Image.get_double]
* [method@Image.set_double]
* [method@Image.get_string]
* [method@Image.set_string]
* [method@Image.print_field]
* [method@Image.get_image]
* [method@Image.set_image]
* [method@Image.set_array_int]
* [method@Image.get_array_int]
* [method@Image.get_array_double]
* [method@Image.set_array_double]
* [method@Image.history_printf]
* [method@Image.history_args]
* [method@Image.get_history]

## Constants

* [const@META_EXIF_NAME]
* [const@META_XMP_NAME]
* [const@META_IPTC_NAME]
* [const@META_PHOTOSHOP_NAME]
* [const@META_ICC_NAME]
* [const@META_IMAGEDESCRIPTION]
* [const@META_RESOLUTION_UNIT]
* [const@META_BITS_PER_SAMPLE]
* [const@META_PALETTE]
* [const@META_LOADER]
* [const@META_SEQUENTIAL]
* [const@META_ORIENTATION]
* [const@META_PAGE_HEIGHT]
* [const@META_N_PAGES]
* [const@META_N_SUBIFDS]
* [const@META_CONCURRENCY]
