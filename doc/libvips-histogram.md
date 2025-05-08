Title: Operator index > By section > Histogram

<!-- libvips/histogram -->

Histograms and look-up tables are 1xn or nx1 images, where n is less than
256 or less than 65536, corresponding to 8- and 16-bit unsigned int images.
They are tagged with a [enum@Interpretation] of
[enum@Vips.Interpretation.HISTOGRAM] and usually displayed by user-interfaces
such as nip2 as plots rather than images.

These functions can be broadly grouped as things to find or build
histograms ([method@Image.hist_find], [method@Image.hist_find_indexed],
[method@Image.hist_find_ndim], [method@Image.buildlut],
[ctor@Image.identity]), operations that manipulate histograms in some way
([method@Image.hist_cum], [method@Image.hist_norm]),
operations to apply histograms ([method@Image.maplut]), and a variety of
utility operations.

A final group of operations build tone curves. These are useful in pre-press
work for adjusting the appearance of images. They are designed for
CIELAB images, but might be useful elsewhere.

## Functions

* [method@Image.maplut]
* [method@Image.percent]
* [method@Image.stdif]
* [method@Image.hist_cum]
* [method@Image.hist_norm]
* [method@Image.hist_equal]
* [method@Image.hist_plot]
* [method@Image.hist_match]
* [method@Image.hist_local]
* [method@Image.hist_ismonotonic]
* [method@Image.hist_entropy]
* [method@Image.case]
