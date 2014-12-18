# vips8 binding for Python

This overrides file adds a few small helper functions to the 
gobject-introspection binding for libvips. It has been tested with python2.7 
and python3.4 and may work for other versions. 

## Documentation

There's a chapter in the libvips API docs on these overrides, see "Using
libvips from Python". 

vips-x.y.z/test has a test suite. Again, the test suite works with python2.7
and python3.4.

## Install

`libvips` need to be built and installed. 

The libvips typelib, `Vips-8.0.typelib`, needs to be on your `GI_TYPELIB_PATH`. It is typically installed somewhere like `/usr/local/lib/girepository-1.0`

You need `pygobject-3.0`. To confirm that it's installed, check that your 
Python `dist-packages` area has a directory called `gi`. For example:

    ls /usr/lib/python2.7/dist-packages/gi

`Vips.py` needs to be in the overrides directory of your gobject-introspection
pygobject area, for example:

    sudo cp Vips.py /usr/lib/python2.7/dist-packages/gi/overrides

or 

    sudo cp Vips.py /usr/lib/python3/dist-packages/gi/overrides

You can optionally pre-compile this file for a small speedup.

For python2.7, you need to install the "future" package. In Ubuntu, for
example, you can do something like:

    sudo apt-get install python-pip
    sudo pip install future

