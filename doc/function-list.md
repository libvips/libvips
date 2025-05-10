Title: Operator index / Alphabetical

libvips has a set of operators, each of which computes some useful image
processing operation. Each operator is implemented as a [class@GObject.Object]
class, for example `VipsGamma`. Classes are identified by their unique
[property@VipsObject:nickname], in this case `gamma`.

From the command-line, C++ and most language bindings, you use the nickname
to call the operator. For example in C++:

```c++
vips::VImage fred = ...;
vips::VImage jim = fred.gamma();
```

or Python:

```python
fred = jim.gamma()
```

libvips has a set of C wrapper functions for calling operators, in this
case [method@Image.gamma]:

```c
VipsImage *fred = ...;
VipsImage *jim;

if (vips_gamma(fred, &jim, NULL))
    ...error;
```

Some operators have many C convenience functions.

# All libvips operators

This table lists all the libvips operators with their C convenience functions
and a short description. It's supposed to be useful for searching. See the
API docs each function links to for more details.

| Operator | Description | C functions |
| -------- | ----------- | ----------- |
| `CMC2LCh` | Transform lch to cmc | [method@Image.CMC2LCh] |
| `CMYK2XYZ` | Transform cmyk to xyz | [method@Image.CMYK2XYZ] |
| `HSV2sRGB` | Transform hsv to srgb | [method@Image.HSV2sRGB] |
| `LCh2CMC` | Transform lch to cmc | [method@Image.LCh2CMC] |
| `LCh2Lab` | Transform lch to lab | [method@Image.LCh2Lab] |
| `Lab2LCh` | Transform lab to lch | [method@Image.Lab2LCh] |
| `Lab2LabQ` | Transform float lab to labq coding | [method@Image.Lab2LabQ] |
| `Lab2LabS` | Transform float lab to signed short | [method@Image.Lab2LabS] |
| `Lab2XYZ` | Transform cielab to xyz | [method@Image.Lab2XYZ] |
| `LabQ2Lab` | Unpack a labq image to float lab | [method@Image.LabQ2Lab] |
| `LabQ2LabS` | Unpack a labq image to short lab | [method@Image.LabQ2LabS] |
| `LabQ2sRGB` | Convert a labq image to srgb | [method@Image.LabQ2sRGB] |
| `LabS2Lab` | Transform signed short lab to float | [method@Image.LabS2Lab] |
| `LabS2LabQ` | Transform short lab to labq coding | [method@Image.LabS2LabQ] |
| `XYZ2CMYK` | Transform xyz to cmyk | [method@Image.XYZ2CMYK] |
| `XYZ2Lab` | Transform xyz to lab | [method@Image.XYZ2Lab] |
| `XYZ2Yxy` | Transform xyz to yxy | [method@Image.XYZ2Yxy] |
| `XYZ2scRGB` | Transform xyz to scrgb | [method@Image.XYZ2scRGB] |
| `Yxy2XYZ` | Transform yxy to xyz | [method@Image.Yxy2XYZ] |
| `abs` | Absolute value of an image | [method@Image.abs] |
| `add` | Add two images | [method@Image.add] |
| `addalpha` | Append an alpha channel | [method@Image.addalpha] |
| `affine` | Affine transform of an image | [method@Image.affine] |
| `analyzeload` | Load an analyze6 image | [ctor@Image.analyzeload] |
| `arrayjoin` | Join an array of images | [func@Image.arrayjoin] |
| `autorot` | Autorotate image by exif tag | [method@Image.autorot] |
| `avg` | Find image average | [method@Image.avg] |
| `bandbool` | Boolean operation across image bands | [method@Image.bandbool], [method@Image.bandand], [method@Image.bandor], [method@Image.bandeor], [method@Image.bandmean] |
| `bandfold` | Fold up x axis into bands | [method@Image.bandfold] |
| `bandjoin` | Bandwise join a set of images | [func@Image.bandjoin], [method@Image.bandjoin2] |
| `bandjoin_const` | Append a constant band to an image | [method@Image.bandjoin_const], [method@Image.bandjoin_const1] |
| `bandmean` | Band-wise average | [method@Image.bandmean] |
| `bandrank` | Band-wise rank of a set of images | [func@Image.bandrank] |
| `bandunfold` | Unfold image bands into x axis | [method@Image.bandunfold] |
| `black` | Make a black image | [ctor@Image.black] |
| `boolean` | Boolean operation on two images | [method@Image.boolean], [method@Image.andimage], [method@Image.orimage], [method@Image.eorimage], [method@Image.lshift], [method@Image.rshift] |
| `boolean_const` | Boolean operations against a constant | [method@Image.boolean_const], [method@Image.andimage_const], [method@Image.orimage_const], [method@Image.eorimage_const], [method@Image.lshift_const], [method@Image.rshift_const], [method@Image.boolean_const1], [method@Image.andimage_const1], [method@Image.orimage_const1], [method@Image.eorimage_const1], [method@Image.lshift_const1], [method@Image.rshift_const1] |
| `buildlut` | Build a look-up table | [method@Image.buildlut] |
| `byteswap` | Byteswap an image | [method@Image.byteswap] |
| `canny` | Canny edge detector | [method@Image.canny] |
| `case` | Use pixel values to pick cases from an array of images | [method@Image.case] |
| `cast` | Cast an image | [method@Image.cast], [method@Image.cast_uchar], [method@Image.cast_char], [method@Image.cast_ushort], [method@Image.cast_short], [method@Image.cast_uint], [method@Image.cast_int], [method@Image.cast_float], [method@Image.cast_double], [method@Image.cast_complex], [method@Image.cast_dpcomplex] |
| `clamp` | Clamp values of an image | [method@Image.clamp] |
| `colourspace` | Convert to a new colorspace | [method@Image.colourspace] |
| `compass` | Convolve with rotating mask | [method@Image.compass] |
| `complex` | Perform a complex operation on an image | [method@Image.complex], [method@Image.polar], [method@Image.rect], [method@Image.conj] |
| `complex2` | Complex binary operations on two images | [method@Image.complex2], [method@Image.cross_phase] |
| `complexform` | Form a complex image from two real images | [method@Image.complexform] |
| `complexget` | Get a component from a complex image | [method@Image.complexget], [method@Image.real], [method@Image.imag] |
| `composite` | Blend an array of images with an array of blend modes | [func@Image.composite] |
| `composite2` | Blend a pair of images with a blend mode | [method@Image.composite2] |
| `conv` | Convolution operation | [method@Image.conv] |
| `conva` | Approximate integer convolution | [method@Image.conva] |
| `convasep` | Approximate separable integer convolution | [method@Image.convasep] |
| `convf` | Float convolution operation | [method@Image.convf] |
| `convi` | Int convolution operation | [method@Image.convi] |
| `convsep` | Separable convolution operation | [method@Image.convsep] |
| `copy` | Copy an image | [method@Image.copy] |
| `countlines` | Count lines in an image | [method@Image.countlines] |
| `csvload` | Load csv | [ctor@Image.csvload] |
| `csvload_source` | Load csv | [ctor@Image.csvload_source] |
| `csvsave` | Save image to csv | [method@Image.csvsave] |
| `csvsave_target` | Save image to csv | [method@Image.csvsave_target] |
| `dE00` | Calculate de00 | [method@Image.dE00] |
| `dE76` | Calculate de76 | [method@Image.dE76] |
| `dECMC` | Calculate decmc | [method@Image.dECMC] |
| `deviate` | Find image standard deviation | [method@Image.deviate] |
| `divide` | Divide two images | [method@Image.divide] |
| `draw_circle` | Draw a circle on an image | [method@Image.draw_circle], [method@Image.draw_circle1] |
| `draw_flood` | Flood-fill an area | [method@Image.draw_flood], [method@Image.draw_flood1] |
| `draw_image` | Paint an image into another image | [method@Image.draw_image] |
| `draw_line` | Draw a line on an image | [method@Image.draw_line], [method@Image.draw_line1] |
| `draw_mask` | Draw a mask on an image | [method@Image.draw_mask], [method@Image.draw_mask1] |
| `draw_rect` | Paint a rectangle on an image | [method@Image.draw_rect], [method@Image.draw_rect1], [method@Image.draw_point], [method@Image.draw_point1] |
| `draw_smudge` | Blur a rectangle on an image | [method@Image.draw_smudge] |
| `dzsave` | Save image to deepzoom file | [method@Image.dzsave] |
| `dzsave_buffer` | Save image to dz buffer | [method@Image.dzsave_buffer] |
| `dzsave_target` | Save image to deepzoom target | [method@Image.dzsave_target] |
| `embed` | Embed an image in a larger image | [method@Image.embed] |
| `extract_area` | Extract an area from an image | [method@Image.extract_area], [method@Image.crop] |
| `extract_band` | Extract band from an image | [method@Image.extract_band] |
| `eye` | Make an image showing the eye's spatial response | [ctor@Image.eye] |
| `falsecolour` | False-color an image | [method@Image.falsecolour] |
| `fastcor` | Fast correlation | [method@Image.fastcor] |
| `fill_nearest` | Fill image zeros with nearest non-zero pixel | [method@Image.fill_nearest] |
| `find_trim` | Search an image for non-edge areas | [method@Image.find_trim] |
| `fitsload` | Load a fits image | [ctor@Image.fitsload] |
| `fitsload_source` | Load fits from a source | [ctor@Image.fitsload_source] |
| `fitssave` | Save image to fits file | [method@Image.fitssave] |
| `flatten` | Flatten alpha out of an image | [method@Image.flatten] |
| `flip` | Flip an image | [method@Image.flip] |
| `float2rad` | Transform float rgb to radiance coding | [method@Image.float2rad] |
| `fractsurf` | Make a fractal surface | [ctor@Image.fractsurf] |
| `freqmult` | Frequency-domain filtering | [method@Image.freqmult] |
| `fwfft` | Forward fft | [method@Image.fwfft] |
| `gamma` | Gamma an image | [method@Image.gamma] |
| `gaussblur` | Gaussian blur | [method@Image.gaussblur] |
| `gaussmat` | Make a gaussian image | [ctor@Image.gaussmat] |
| `gaussnoise` | Make a gaussnoise image | [ctor@Image.gaussnoise] |
| `getpoint` | Read a point from an image | [method@Image.getpoint] |
| `gifload` | Load gif with libnsgif | [ctor@Image.gifload] |
| `gifload_buffer` | Load gif with libnsgif | [ctor@Image.gifload_buffer] |
| `gifload_source` | Load gif from source | [ctor@Image.gifload_source] |
| `gifsave` | Save as gif | [method@Image.gifsave] |
| `gifsave_buffer` | Save as gif | [method@Image.gifsave_buffer] |
| `gifsave_target` | Save as gif | [method@Image.gifsave_target] |
| `globalbalance` | Global balance an image mosaic | [method@Image.globalbalance] |
| `gravity` | Place an image within a larger image with a certain gravity | [method@Image.gravity] |
| `grey` | Make a grey ramp image | [ctor@Image.grey] |
| `grid` | Grid an image | [method@Image.grid] |
| `heifload` | Load a heif image | [ctor@Image.heifload] |
| `heifload_buffer` | Load a heif image | [ctor@Image.heifload_buffer] |
| `heifload_source` | Load a heif image | [ctor@Image.heifload_source] |
| `heifsave` | Save image in heif format | [method@Image.heifsave] |
| `heifsave_buffer` | Save image in heif format | [method@Image.heifsave_buffer] |
| `heifsave_target` | Save image in heif format | [method@Image.heifsave_target] |
| `hist_cum` | Form cumulative histogram | [method@Image.hist_cum] |
| `hist_entropy` | Estimate image entropy | [method@Image.hist_entropy] |
| `hist_equal` | Histogram equalisation | [method@Image.hist_equal] |
| `hist_find` | Find image histogram | [method@Image.hist_find] |
| `hist_find_indexed` | Find indexed image histogram | [method@Image.hist_find_indexed] |
| `hist_find_ndim` | Find n-dimensional image histogram | [method@Image.hist_find_ndim] |
| `hist_ismonotonic` | Test for monotonicity | [method@Image.hist_ismonotonic] |
| `hist_local` | Local histogram equalisation | [method@Image.hist_local] |
| `hist_match` | Match two histograms | [method@Image.hist_match] |
| `hist_norm` | Normalise histogram | [method@Image.hist_norm] |
| `hist_plot` | Plot histogram | [method@Image.hist_plot] |
| `hough_circle` | Find hough circle transform | [method@Image.hough_circle] |
| `hough_line` | Find hough line transform | [method@Image.hough_line] |
| `icc_export` | Output to device with icc profile | [method@Image.icc_export] |
| `icc_import` | Import from device with icc profile | [method@Image.icc_import] |
| `icc_transform` | Transform between devices with icc profiles | [method@Image.icc_transform] |
| `identity` | Make a 1d image where pixel values are indexes | [ctor@Image.identity] |
| `ifthenelse` | Ifthenelse an image | [method@Image.ifthenelse] |
| `insert` | Insert image @sub into @main at @x, @y | [method@Image.insert] |
| `invert` | Invert an image | [method@Image.invert] |
| `invertlut` | Build an inverted look-up table | [method@Image.invertlut] |
| `invfft` | Inverse fft | [method@Image.invfft] |
| `join` | Join a pair of images | [method@Image.join] |
| `jp2kload` | Load jpeg2000 image | [ctor@Image.jp2kload] |
| `jp2kload_buffer` | Load jpeg2000 image | [ctor@Image.jp2kload_buffer] |
| `jp2kload_source` | Load jpeg2000 image | [ctor@Image.jp2kload_source] |
| `jp2ksave` | Save image in jpeg2000 format | [method@Image.jp2ksave] |
| `jp2ksave_buffer` | Save image in jpeg2000 format | [method@Image.jp2ksave_buffer] |
| `jp2ksave_target` | Save image in jpeg2000 format | [method@Image.jp2ksave_target] |
| `jpegload` | Load jpeg from file | [ctor@Image.jpegload] |
| `jpegload_buffer` | Load jpeg from buffer | [ctor@Image.jpegload_buffer] |
| `jpegload_source` | Load image from jpeg source | [ctor@Image.jpegload_source] |
| `jpegsave` | Save image to jpeg file | [method@Image.jpegsave] |
| `jpegsave_buffer` | Save image to jpeg buffer | [method@Image.jpegsave_buffer] |
| `jpegsave_mime` | Save image to jpeg mime | [method@Image.jpegsave_mime] |
| `jpegsave_target` | Save image to jpeg target | [method@Image.jpegsave_target] |
| `jxlload` | Load jpeg-xl image | [ctor@Image.jxlload] |
| `jxlload_buffer` | Load jpeg-xl image | [ctor@Image.jxlload_buffer] |
| `jxlload_source` | Load jpeg-xl image | [ctor@Image.jxlload_source] |
| `jxlsave` | Save image in jpeg-xl format | [method@Image.jxlsave] |
| `jxlsave_buffer` | Save image in jpeg-xl format | [method@Image.jxlsave_buffer] |
| `jxlsave_target` | Save image in jpeg-xl format | [method@Image.jxlsave_target] |
| `labelregions` | Label regions in an image | [method@Image.labelregions] |
| `linear` | Calculate (a * in + b) | [method@Image.linear], [method@Image.linear1] |
| `linecache` | Cache an image as a set of lines | [method@Image.linecache] |
| `logmat` | Make a laplacian of gaussian image | [ctor@Image.logmat] |
| `magickload` | Load file with imagemagick | [ctor@Image.magickload] |
| `magickload_buffer` | Load buffer with imagemagick | [ctor@Image.magickload_buffer] |
| `magicksave` | Save file with imagemagick | [method@Image.magicksave] |
| `magicksave_buffer` | Save image to magick buffer | [method@Image.magicksave_buffer] |
| `mapim` | Resample with a map image | [method@Image.mapim] |
| `maplut` | Map an image though a lut | [method@Image.maplut] |
| `mask_butterworth` | Make a butterworth filter | [ctor@Image.mask_butterworth] |
| `mask_butterworth_band` | Make a butterworth_band filter | [ctor@Image.mask_butterworth_band] |
| `mask_butterworth_ring` | Make a butterworth ring filter | [ctor@Image.mask_butterworth_ring] |
| `mask_fractal` | Make fractal filter | [ctor@Image.mask_fractal] |
| `mask_gaussian` | Make a gaussian filter | [ctor@Image.mask_gaussian] |
| `mask_gaussian_band` | Make a gaussian filter | [ctor@Image.mask_gaussian_band] |
| `mask_gaussian_ring` | Make a gaussian ring filter | [ctor@Image.mask_gaussian_ring] |
| `mask_ideal` | Make an ideal filter | [ctor@Image.mask_ideal] |
| `mask_ideal_band` | Make an ideal band filter | [ctor@Image.mask_ideal_band] |
| `mask_ideal_ring` | Make an ideal ring filter | [ctor@Image.mask_ideal_ring] |
| `match` | First-order match of two images | [method@Image.match] |
| `math` | Apply a math operation to an image | [method@Image.math], [method@Image.sin], [method@Image.cos], [method@Image.tan], [method@Image.asin], [method@Image.acos], [method@Image.atan], [method@Image.sinh], [method@Image.cosh], [method@Image.tanh], [method@Image.asinh], [method@Image.acosh], [method@Image.atanh], [method@Image.exp], [method@Image.exp10], [method@Image.log], [method@Image.log10] |
| `math2` | Binary math operations | [method@Image.math2], [method@Image.pow], [method@Image.wop], [method@Image.atan2] |
| `math2_const` | Binary math operations with a constant | [method@Image.math2_const], [method@Image.andimage_const], [method@Image.orimage_const], [method@Image.eorimage_const], [method@Image.lshift_const], [method@Image.rshift_const], [method@Image.math2_const1], [method@Image.andimage_const1], [method@Image.orimage_const1], [method@Image.eorimage_const1], [method@Image.lshift_const1], [method@Image.rshift_const1] |
| `matload` | Load mat from file | [ctor@Image.matload] |
| `matrixinvert` | Invert a matrix | [method@Image.matrixinvert] |
| `matrixload` | Load matrix | [ctor@Image.matrixload] |
| `matrixload_source` | Load matrix | [ctor@Image.matrixload_source] |
| `matrixmultiply` | Multiply two matrices | [method@Image.matrixmultiply] |
| `matrixprint` | Print matrix | [method@Image.matrixprint] |
| `matrixsave` | Save image to matrix | [method@Image.matrixsave] |
| `matrixsave_target` | Save image to matrix | [method@Image.matrixsave_target] |
| `max` | Find image maximum | [method@Image.max] |
| `maxpair` | Maximum of a pair of images | [method@Image.maxpair] |
| `measure` | Measure a set of patches on a color chart | [method@Image.measure] |
| `merge` | Merge two images | [method@Image.merge] |
| `min` | Find image minimum | [method@Image.min] |
| `minpair` | Minimum of a pair of images | [method@Image.minpair] |
| `morph` | Morphology operation | [method@Image.morph] |
| `mosaic` | Mosaic two images | [method@Image.mosaic] |
| `mosaic1` | First-order mosaic of two images | [method@Image.mosaic1] |
| `msb` | Pick most-significant byte from an image | [method@Image.msb] |
| `multiply` | Multiply two images | [method@Image.multiply] |
| `niftiload` | Load nifti volume | [ctor@Image.niftiload] |
| `niftiload_source` | Load nifti volumes | [ctor@Image.niftiload_source] |
| `niftisave` | Save image to nifti file | [method@Image.niftisave] |
| `openexrload` | Load an openexr image | [ctor@Image.openexrload] |
| `openslideload` | Load file with openslide | [ctor@Image.openslideload] |
| `openslideload_source` | Load source with openslide | [ctor@Image.openslideload_source] |
| `pdfload` | Load pdf from file | [ctor@Image.pdfload] |
| `pdfload_buffer` | Load pdf from buffer | [ctor@Image.pdfload_buffer] |
| `pdfload_source` | Load pdf from source | [ctor@Image.pdfload_source] |
| `percent` | Find threshold for percent of pixels | [method@Image.percent] |
| `perlin` | Make a perlin noise image | [ctor@Image.perlin] |
| `phasecor` | Calculate phase correlation | [method@Image.phasecor] |
| `pngload` | Load png from file | [ctor@Image.pngload] |
| `pngload_buffer` | Load png from buffer | [ctor@Image.pngload_buffer] |
| `pngload_source` | Load png from source | [ctor@Image.pngload_source] |
| `pngsave` | Save image to file as png | [method@Image.pngsave] |
| `pngsave_buffer` | Save image to buffer as png | [method@Image.pngsave_buffer] |
| `pngsave_target` | Save image to target as png | [method@Image.pngsave_target] |
| `ppmload` | Load ppm from file | [ctor@Image.ppmload] |
| `ppmload_source` | Load ppm base class | [ctor@Image.ppmload_source] |
| `ppmsave` | Save image to ppm file | [method@Image.ppmsave] |
| `ppmsave_target` | Save to ppm | [method@Image.ppmsave_target] |
| `premultiply` | Premultiply image alpha | [method@Image.premultiply] |
| `prewitt` | Prewitt edge detector | [method@Image.prewitt] |
| `profile` | Find image profiles | [method@Image.profile] |
| `profile_load` | Load named icc profile | [ctor@Blob.profile_load] |
| `project` | Find image projections | [method@Image.project] |
| `quadratic` | Resample an image with a quadratic transform | [method@Image.quadratic] |
| `rad2float` | Unpack radiance coding to float rgb | [method@Image.rad2float] |
| `radload` | Load a radiance image from a file | [ctor@Image.radload] |
| `radload_buffer` | Load rad from buffer | [ctor@Image.radload_buffer] |
| `radload_source` | Load rad from source | [ctor@Image.radload_source] |
| `radsave` | Save image to radiance file | [method@Image.radsave] |
| `radsave_buffer` | Save image to radiance buffer | [method@Image.radsave_buffer] |
| `radsave_target` | Save image to radiance target | [method@Image.radsave_target] |
| `rank` | Rank filter | [method@Image.rank], [method@Image.median] |
| `rawload` | Load raw data from a file | [ctor@Image.rawload] |
| `rawsave` | Save image to raw file | [method@Image.rawsave] |
| `rawsave_buffer` | Write raw image to buffer | [method@Image.rawsave_buffer] |
| `rawsave_target` | Write raw image to target | [method@Image.rawsave_target] |
| `recomb` | Linear recombination with matrix | [method@Image.recomb] |
| `reduce` | Reduce an image | [method@Image.reduce] |
| `reduceh` | Shrink an image horizontally | [method@Image.reduceh] |
| `reducev` | Shrink an image vertically | [method@Image.reducev] |
| `relational` | Relational operation on two images | [method@Image.relational], [method@Image.equal], [method@Image.notequal], [method@Image.less], [method@Image.lesseq], [method@Image.more], [method@Image.moreeq] |
| `relational_const` | Relational operations against a constant | [method@Image.relational_const], [method@Image.equal_const], [method@Image.notequal_const], [method@Image.less_const], [method@Image.lesseq_const], [method@Image.more_const], [method@Image.moreeq_const], [method@Image.relational_const1], [method@Image.equal_const1], [method@Image.notequal_const1], [method@Image.less_const1], [method@Image.lesseq_const1], [method@Image.more_const1], [method@Image.moreeq_const1] |
| `remainder` | Remainder after integer division of two images | [method@Image.remainder] |
| `remainder_const` | Remainder after integer division of an image and a constant | [method@Image.remainder_const], [method@Image.remainder_const1] |
| `remosaic` | Rebuild an mosaiced image | [method@Image.remosaic] |
| `replicate` | Replicate an image | [method@Image.replicate] |
| `resize` | Resize an image | [method@Image.resize] |
| `rot` | Rotate an image | [method@Image.rot] |
| `rot45` | Rotate an image | [method@Image.rot45] |
| `rotate` | Rotate an image by a number of degrees | [method@Image.rotate] |
| `round` | Perform a round function on an image | [method@Image.round], [method@Image.floor], [method@Image.ceil], [method@Image.rint] |
| `sRGB2HSV` | Transform srgb to hsv | [method@Image.sRGB2HSV] |
| `sRGB2scRGB` | Convert an srgb image to scrgb | [method@Image.sRGB2scRGB] |
| `scRGB2BW` | Convert scrgb to bw | [method@Image.scRGB2BW] |
| `scRGB2XYZ` | Transform scrgb to xyz | [method@Image.scRGB2XYZ] |
| `scRGB2sRGB` | Convert scrgb to srgb | [method@Image.scRGB2sRGB] |
| `scale` | Scale an image to uchar | [method@Image.scale] |
| `scharr` | Scharr edge detector | [method@Image.scharr] |
| `sdf` | Create an sdf image | [ctor@Image.sdf] |
| `sequential` | Check sequential access | [method@Image.sequential] |
| `sharpen` | Unsharp masking for print | [method@Image.sharpen] |
| `shrink` | Shrink an image | [method@Image.shrink] |
| `shrinkh` | Shrink an image horizontally | [method@Image.shrinkh] |
| `shrinkv` | Shrink an image vertically | [method@Image.shrinkv] |
| `sign` | Unit vector of pixel | [method@Image.sign] |
| `similarity` | Similarity transform of an image | [method@Image.similarity] |
| `sines` | Make a 2d sine wave | [ctor@Image.sines] |
| `smartcrop` | Extract an area from an image | [method@Image.smartcrop] |
| `sobel` | Sobel edge detector | [method@Image.sobel] |
| `spcor` | Spatial correlation | [method@Image.spcor] |
| `spectrum` | Make displayable power spectrum | [method@Image.spectrum] |
| `stats` | Find many image stats | [method@Image.stats] |
| `stdif` | Statistical difference | [method@Image.stdif] |
| `subsample` | Subsample an image | [method@Image.subsample] |
| `subtract` | Subtract two images | [method@Image.subtract] |
| `sum` | Sum an array of images | [func@Image.sum] |
| `svgload` | Load svg with rsvg | [ctor@Image.svgload] |
| `svgload_buffer` | Load svg with rsvg | [ctor@Image.svgload_buffer] |
| `svgload_source` | Load svg from source | [ctor@Image.svgload_source] |
| `switch` | Find the index of the first non-zero pixel in tests | [func@Image.switch] |
| `system` | Run an external command | [ctor@Image.system] |
| `text` | Make a text image | [ctor@Image.text] |
| `thumbnail` | Generate thumbnail from file | [ctor@Image.thumbnail] |
| `thumbnail_buffer` | Generate thumbnail from buffer | [ctor@Image.thumbnail_buffer] |
| `thumbnail_image` | Generate thumbnail from image | [method@Image.thumbnail_image] |
| `thumbnail_source` | Generate thumbnail from source | [ctor@Image.thumbnail_source] |
| `tiffload` | Load tiff from file | [ctor@Image.tiffload] |
| `tiffload_buffer` | Load tiff from buffer | [ctor@Image.tiffload_buffer] |
| `tiffload_source` | Load tiff from source | [ctor@Image.tiffload_source] |
| `tiffsave` | Save image to tiff file | [method@Image.tiffsave] |
| `tiffsave_buffer` | Save image to tiff buffer | [method@Image.tiffsave_buffer] |
| `tiffsave_target` | Save image to tiff target | [method@Image.tiffsave_target] |
| `tilecache` | Cache an image as a set of tiles | [method@Image.tilecache] |
| `tonelut` | Build a look-up table | [ctor@Image.tonelut] |
| `transpose3d` | Transpose3d an image | [method@Image.transpose3d] |
| `unpremultiply` | Unpremultiply image alpha | [method@Image.unpremultiply] |
| `vipsload` | Load vips from file | [ctor@Image.vipsload] |
| `vipsload_source` | Load vips from source | [ctor@Image.vipsload_source] |
| `vipssave` | Save image to file in vips format | [method@Image.vipssave] |
| `vipssave_target` | Save image to target in vips format | [method@Image.vipssave_target] |
| `webpload` | Load webp from file | [ctor@Image.webpload] |
| `webpload_buffer` | Load webp from buffer | [ctor@Image.webpload_buffer] |
| `webpload_source` | Load webp from source | [ctor@Image.webpload_source] |
| `webpsave` | Save as webp | [method@Image.webpsave] |
| `webpsave_buffer` | Save as webp | [method@Image.webpsave_buffer] |
| `webpsave_mime` | Save image to webp mime | [method@Image.webpsave_mime] |
| `webpsave_target` | Save as webp | [method@Image.webpsave_target] |
| `worley` | Make a worley noise image | [ctor@Image.worley] |
| `wrap` | Wrap image origin | [method@Image.wrap] |
| `xyz` | Make an image where pixel values are coordinates | [ctor@Image.xyz] |
| `zone` | Make a zone plate | [ctor@Image.zone] |
| `zoom` | Zoom an image | [method@Image.zoom] |
