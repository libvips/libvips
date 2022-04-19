---
title: New pyvips and php-vips
---

pyvips and php-vips have launched interesting new versions.

# pyvips

pyvips version 2.2 is just out and thanks to work by erdmann features a range
of useful new features.

## PIL and numpy

pyvips now has much better integration with numpy and PIL. For example,
you can make a Numpy array like this:

```python
import numpy as np

a = (np.random.random((100, 100, 3)) * 255).astype(np.uint8)
```

Then wrap a pyvips image around it using
[`Image.new_from_array`](https://libvips.github.io/pyvips/vimage.html#pyvips.Image.new_from_array):

```python
import pyvips

image = pyvips.Image.new_from_array(a)
```

pyvips will even guess a sensible interpretaion for you (sRGB in this case),
or you can specify with the optional `interpretation=` argument. This works
by sharing a memory buffer between the two libraries, so no data is copied
or duplicated, just a pointer.

Going the other way, you can make a numpy array from a pyvips image using
[`Image.numpy()`](https://libvips.github.io/pyvips/vimage.html#pyvips.Image.numpy):

```python
a1 = image.numpy()
```

Or just use numpy's `asarray()`:

```python
a1 = np.asarray(image)
```

Again, there's no copying of data, just a pointer, so this is a fast way
for numpy to load many image formats.

You can use the same method to make a PIL image:

```python
import PIL.Image

image = pyvips.Image.black(100, 100, bands=3)
pil_image = PIL.Image.fromarray(image.numpy())
```

Or to make a pyvips image from PIL:

```python
pil_image = PIL.Image.new('RGB', (60, 30), color='red')
image = pyvips.Image.new_from_array(pil_image)
```

Again, no copying.

## Improved indexing

Band indexing now supports an optional step. For example:

```python
iamge = image[::-1]
```

Will reverse the bands in an image, so RGB becomes BGR. You
can also index with a list of bools. The docs have [all the
details](https://libvips.github.io/pyvips/vimage.html?highlight=getitem#pyvips.Image.__getitem__).

## Other improvements

There's a new
[`invalidate`](https://libvips.github.io/pyvips/vimage.html?highlight=invalidate#pyvips.Image.invalidate) method you can use to throw images out of the
various libvips caches, a useful speedup for pyvips method call, and support
for `Path` objects for load and save.

# php-vips

Version 2.0 of [php-vips](https://github.com/libvips/php-vips)
has been rebuilt on top of php's new [FFI
module](https://www.php.net/manual/en/book.ffi.php). This new version should
be much simpler to maintain, develop, support and install. 

php-vips used to come in two parts: there was a PHP extension written in C
called [php-vips-ext](https://github.com/libvips/php-vips-ext) which gave
very low-level access to libvips, and a pure PHP layer (called php-vips) which
implemented the public API.

This setup was tricky to manage for a range of reasons, but maintaining the C
extension was the hardest part. It was nasty to install as well, with many
users having issues getting it to work. 

PHP now has an FFI interface to external libraries, so we've rewritten
php-vips to use that to make calls directly into libvips. The public API
hasn't changed, so everyone's code should still work.

