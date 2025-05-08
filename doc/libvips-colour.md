Title: Operator index > By section > Colour

<!-- libvips/colour -->

These operators let you transform coordinates and images between colour
spaces, calculate colour differences, and move to and from device spaces.

All operations process colour from the first few bands and pass other bands
through unaltered. This means you can operate on images with alpha channels
safely. If you move to or from 16-bit RGB, any alpha channels are rescaled
for you.

Radiance images have four 8-bits bands and store 8 bits of R, G and B and
another 8 bits of exponent, common to all channels. They are widely used in
the HDR imaging community.

The colour functions can be divided into three main groups. First,
functions to transform images between the different colour spaces supported
by libvips:
[enum@Vips.Interpretation.SRGB], [enum@Vips.Interpretation.SCRGB],
[enum@Vips.Interpretation.B_W], [enum@Vips.Interpretation.XYZ],
[enum@Vips.Interpretation.YXY], [enum@Vips.Interpretation.LAB],
[enum@Vips.Interpretation.LCH], and [enum@Vips.Interpretation.CMC].

There are also a set of minor colourspaces which are one of the above in a
slightly different format:
[enum@Vips.Interpretation.LAB], [enum@Vips.Interpretation.LABQ],
[enum@Vips.Interpretation.LABS], [enum@Vips.Interpretation.LCH],
[enum@Vips.Interpretation.RGB16], and [enum@Vips.Interpretation.GREY16].

Use [method@Image.colourspace] to move an image to a target colourspace
using the best sequence of colour transform operations.

Secondly, there are a set of operations for calculating colour difference
metrics. Finally, libvips wraps LittleCMS and uses it to provide a set of
operations for reading and writing images with ICC profiles.

This figure shows how the libvips colour spaces interconvert:

![Interconvert](interconvert.png)

The colour spaces supported by libvips are:

- [enum@Vips.Interpretation.LAB]: CIELAB '76 colourspace with a D65 white.
  This uses three floats for each band, and bands have the obvious range.<br /><br />
  There are two variants, [enum@Vips.Interpretation.LABQ] and
  [enum@Vips.Interpretation.LABS], which use ints to store values. These are
  less precise, but can be quicker to store and process.<br /><br />
  [enum@Vips.Interpretation.LCH] is the same, but with a\*b\* as polar
  coordinates. Hue is expressed in degrees.

- [enum@Vips.Interpretation.XYZ]: CIE XYZ. This uses three floats.
  See [const@D75_X0] and friends for values for the ranges under various
  illuminants.<br /><br />
  [enum@Vips.Interpretation.YXY] is the same, but with little x and y.

- [enum@Vips.Interpretation.SCRGB]: a linear colourspace with the sRGB
  primaries. This is useful if you need linear light and don't care
  much what the primaries are.<br /><br />
  Linearization is performed with the usual sRGB equations, see below.

- [enum@Vips.Interpretation.SRGB]: the standard sRGB colourspace, see:
  [wikipedia sRGB](http://en.wikipedia.org/wiki/SRGB).<br /><br />
  This uses three 8-bit values for each of RGB.<br /><br />
  [enum@Vips.Interpretation.RGB16] is the same, but using three 16-bit values
  for RGB.<br /><br />
  [enum@Vips.Interpretation.HSV] is sRGB, but in polar coordinates.
  [enum@Vips.Interpretation.LCH] is much better, only use HSV if you have to.

- [enum@Vips.Interpretation.B_W]: a monochrome image, roughly G from sRGB.
  The grey value is calculated in linear [enum@Vips.Interpretation.SCRGB]
  space with RGB ratios 0.2126, 0.7152, 0.0722 as defined by CIE 1931 linear
  luminance.<br /><br />
  [enum@Vips.Interpretation.GREY16] is the same, but using 16 bits.

- [enum@Vips.Interpretation.CMC]: a colour space based on the CMC(1:1)
  colour difference measurement. This is a highly uniform colour space,
  and much better than CIELAB for expressing small differences.<br /><br />
  The CMC colourspace is described in “Uniform Colour Space Based on the
  CMC(l:c) Colour-difference Formula”, M R Luo and B Rigg, Journal of the
  Society of Dyers and Colourists, vol 102, 1986. Distances in this
  colourspace approximate, within 10% or so, differences in the CMC(l:c)
  colour difference formula.<br /><br />
  You can calculate metrics like CMC(2:1) by scaling the spaces before
  finding differences.

## Functions

* [method@Image.colourspace_issupported]
* [method@Image.colourspace]
* [method@Image.LabQ2sRGB]
* [method@Image.rad2float]
* [method@Image.float2rad]
* [method@Image.LabS2LabQ]
* [method@Image.LabQ2LabS]
* [method@Image.LabQ2Lab]
* [method@Image.Lab2LabQ]
* [method@Image.LCh2Lab]
* [method@Image.Lab2LCh]
* [method@Image.Lab2XYZ]
* [method@Image.XYZ2Lab]
* [method@Image.XYZ2scRGB]
* [method@Image.scRGB2sRGB]
* [method@Image.scRGB2BW]
* [method@Image.sRGB2scRGB]
* [method@Image.scRGB2XYZ]
* [method@Image.HSV2sRGB]
* [method@Image.sRGB2HSV]
* [method@Image.LCh2CMC]
* [method@Image.CMC2LCh]
* [method@Image.XYZ2Yxy]
* [method@Image.Yxy2XYZ]
* [method@Image.LabS2Lab]
* [method@Image.Lab2LabS]
* [method@Image.CMYK2XYZ]
* [method@Image.XYZ2CMYK]
* [ctor@Blob.profile_load]
* [func@icc_present]
* [method@Image.icc_transform]
* [method@Image.icc_import]
* [method@Image.icc_export]
* [method@Image.icc_ac2rc]
* [func@icc_is_compatible_profile]
* [method@Image.dE76]
* [method@Image.dE00]
* [method@Image.dECMC]
* [func@col_Lab2XYZ]
* [func@col_XYZ2Lab]
* [func@col_ab2h]
* [func@col_ab2Ch]
* [func@col_Ch2ab]
* [func@col_L2Lcmc]
* [func@col_C2Ccmc]
* [func@col_Ch2hcmc]
* [func@col_make_tables_CMC]
* [func@col_Lcmc2L]
* [func@col_Ccmc2C]
* [func@col_Chcmc2h]
* [func@col_sRGB2scRGB_8]
* [func@col_sRGB2scRGB_16]
* [func@col_sRGB2scRGB_8_noclip]
* [func@col_sRGB2scRGB_16_noclip]
* [func@col_scRGB2XYZ]
* [func@col_XYZ2scRGB]
* [func@col_scRGB2sRGB_8]
* [func@col_scRGB2sRGB_16]
* [func@col_scRGB2BW_16]
* [func@col_scRGB2BW_8]
* [func@pythagoras]
* [func@col_dE00]

## Constants

* [const@D93_X0]
* [const@D93_Y0]
* [const@D93_Z0]
* [const@D75_X0]
* [const@D75_Y0]
* [const@D75_Z0]
* [const@D65_X0]
* [const@D65_Y0]
* [const@D65_Z0]
* [const@D55_X0]
* [const@D55_Y0]
* [const@D55_Z0]
* [const@D50_X0]
* [const@D50_Y0]
* [const@D50_Z0]
* [const@A_X0]
* [const@A_Y0]
* [const@A_Z0]
* [const@B_X0]
* [const@B_Y0]
* [const@B_Z0]
* [const@C_X0]
* [const@C_Y0]
* [const@C_Z0]
* [const@E_X0]
* [const@E_Y0]
* [const@E_Z0]
* [const@D3250_X0]
* [const@D3250_Y0]
* [const@D3250_Z0]

## Enumerations

* [enum@Intent]
* [enum@PCS]
