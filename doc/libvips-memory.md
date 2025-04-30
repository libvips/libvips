Title: Operator index > By section > Memory

<!-- libvips/iofuncs/memory.c -->

These functions cover two main areas.

First, some simple utility functions over the underlying [func@GLib.malloc] /
[func@GLib.free] functions. Memory that is allocated and freed using these
functions is interchangeable with any other GLib library.

Second, a pair of functions, [func@tracked_malloc] and [func@tracked_free],
which are NOT compatible. If you [func@GLib.free] memory that has been
allocated with [func@tracked_malloc] you will see crashes.

The tracked functions are only suitable for large allocations internal to the
library, for example pixel buffers. libvips watches the total amount of live
tracked memory and uses this information to decide when to trim caches.

## Functions

* [func@malloc]
* [func@strdup]
* [func@tracked_free]
* [func@tracked_aligned_free]
* [func@tracked_malloc]
* [func@tracked_aligned_alloc]
* [func@tracked_get_mem]
* [func@tracked_get_mem_highwater]
* [func@tracked_get_allocs]
* [func@tracked_open]
* [func@tracked_close]
* [func@tracked_get_files]

## Function macros

* [func@FREEF]
* [func@FREE]
* [func@SETSTR]
* [func@MALLOC]
* [func@NEW]
* [func@ARRAY]
