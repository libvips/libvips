# vips8 binding for Python

This overrides file adds a few small helper functions to the 
gobject-introspection binding for libvips.

There's a chapter in the libvips API docs on these overrides, see "Using
libvips from Python". 

vips-x.y.z/test has a test suite. 

Vips.py needs to be in the overrides directory of your gobject-introspection
pygobject area, for example:

    sudo cp Vips.py /usr/lib/python2.7/dist-packages/gi/overrides

