vips8 binding for Python

This binding adds a few small helper functions to the gobject-introspection
binding for libvips.

The test/ directory has a test suite. 

Vips.py needs to be in the overrides directory of your gobject-introspection
pygobject area, for example:

sudo cp Vips.py /usr/lib/python2.7/dist-packages/gi/overrides


