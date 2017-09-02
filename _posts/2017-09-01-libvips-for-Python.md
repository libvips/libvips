---
title: libvips for Python
---

There's a new libvips binding for Python. It has the same API as the one that
comes with libvips (it passes the same test suite), it's very easy to install
on Linux, macOS and Windows, it works with any Python, it should be 
smaller and more stable, and it has nice new documentation:

[https://jcupitt.github.io/pyvips/](https://jcupitt.github.io/pyvips/)

The README in the repository for the binding has more details, including some
install notes and an example:

[https://github.com/jcupitt/pyvips](https://github.com/jcupitt/pyvips)

But briefly, just get the libvips shared library on your system and enter:

	pip install pyvips

## Why a new binding?

The Python binding included in libvips works, but porting and installation
are more difficult than they should be.

This new binding is:

* Compatible with the old Python binding (it runs the same test suite,
  unmodified).

* Easier to install, since the stack is much smaller, and there are
  no issues with the overrides directory.

* Faster, since we can implement Buffer and save copying large memory areas
  during `new_from_buffer` and `new_from_memory`.

* Faster, since it is lighter. For example, the Python binding in libvips 
  runs the test suite in 84s on my laptop, this new binding runs a larger test
  suite in 65s.

* Portable across at least CPython and PyPy.

* Easy to package for pip. 

## How it works

This binding is based on cffi, the FFI package for Python. It opens the libvips
shared library and uses the libvips introspection system to make the operations 
it finds appear as members of the `pyvips.Image` class. 

This dynamic approach via ffi has several nice properties:

* As operations are added to libvips, they will immediately appear in
  `pyvips`, with no maintenance effort required. This binding should
  always be up to date.

* The whole binding, exposing all 300 vips operations, is less than 3,000
  lines of Python, and most of that is things like the set of operator
  overloads -- the actual binding is tiny. 
  
* There is no native code, so it'll work immediately on any platform 
  that has Python, cffi and a libvips shared library.

* Since there's no middleware, we can make the binding do exactly what we want.
  Buffer objects (or memoryview) were not supported by gobject-introspection,
  but now we can implement them, and save a lot of memory and copying when 
  moving images between libvips, PIL and NumPy.

## What's next?

The Python binding that comes with libvips will be kept for a while, but from
libvips 8.6 onwards, we plan to point people towards `pyvips` instead.
