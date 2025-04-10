Title: Operator index > By section > Initialisation

<!-- libvips/iofuncs/init.c -->

These functions handle the initialization, finalization, version retrieval,
and relocation for libvips.

libvips is a relocatable package, meaning you can move the directory tree you
compiled it to at runtime and it will still be able to find all data files.
This is required for macOS and Windows, but slightly unusual in the Unix
world. See [func@init] and [func@guess_prefix].

## Functions

* [func@max_coord_get]
* [func@init]
* [func@get_argv0]
* [func@get_prgname]
* [func@shutdown]
* [func@thread_shutdown]
* [func@add_option_entries]
* [func@leak_set]
* [func@block_untrusted_set]
* [func@version_string]
* [func@version]
* [func@guess_prefix]
* [func@guess_libdir]

## Function macros

* [func@INIT]

## Constants

* [const@DEFAULT_MAX_COORD]
* [const@ENABLE_DEPRECATED]
* [const@LIBRARY_AGE]
* [const@LIBRARY_CURRENT]
* [const@LIBRARY_REVISION]
* [const@MAJOR_VERSION]
* [const@MICRO_VERSION]
* [const@MINOR_VERSION]
* [const@VERSION]
* [const@VERSION_STRING]
