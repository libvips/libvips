---
title: pyvips in conda
---

Thanks to work by Sebastian Luna-Valero (sebastian-luna-valero) and others, 
pyvips is now in conda!

# Install

To install, first [install
Anaconda](https://docs.anaconda.com/anaconda/install/).

pyvips is is `conda-forge`, the community conda channel: 

<a href="https://anaconda.org/conda-forge/pyvips">https://anaconda.org/conda-forge/pyvips</a>

First, create a python environment to install pyvips in. You can use any Python
version, but 3.7 is the current latest:

  conda create --name vips python=3.7

And activate it:

  conda activate vips

To install, enter:

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


