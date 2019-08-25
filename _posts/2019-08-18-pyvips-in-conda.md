---
title: pyvips in conda
---

Thanks to work by Sebastian Luna-Valero (@sebastian-luna-valero) and others, 
pyvips is now in conda!

It includes a libvips binary with most optional packages enabled, including
things like openslide and matio. It is currently missing HEIC and
libjpeg-turbo, but perhaps they will come.

Windows support is blocked on `gdk-pixbuf`, unfortunately. The [pyvips
README](https://github.com/libvips/pyvips/blob/master/README.rst) has some
notes on Windows install.

# Install

To install, first [install
Anaconda](https://docs.anaconda.com/anaconda/install/).

Next, create a python environment to install pyvips in. You can use any Python
version, but 3.7 is the current latest:

    conda create --name vips python=3.7

And activate it:

    conda activate vips

[pyvips is in `conda-forge`](https://anaconda.org/conda-forge/pyvips), the
community conda channel, so install with:

    conda install --channel conda-forge pyvips

# Test

You should now be able to use pyvips. For example:

```
(vips) john@katamata:~$ python
Python 3.7.4 (default, Aug 13 2019, 15:17:50) 
[Clang 4.0.1 (tags/RELEASE_401/final)] :: Anaconda, Inc. on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import pyvips
>>> x = pyvips.Image.new_from_file("/Users/john/pics/openslide/normal_091.tif")
>>> x.width
97792
>>> x.height
215552
```

# Cleanup

Step out of the `vips` environment when you are done testing:

    conda deactivate

And you can now remove the `vips` environment.

    conda remove --name vips --all


