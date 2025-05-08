Title: Operator index > By section > Arithmetic

<!-- libvips/arithmetic -->

These operations perform pixel arithmetic, that is, they perform an
arithmetic operation, such as addition, on every pixel in an image or a
pair of images. All (except in a few cases noted below) will work with
images of any type or any mixture of types, of any size and of any number
of bands.

For binary operations, if the number of bands differs, one of the images
must have one band. In this case, an n-band image is formed from the
one-band image by joining n copies of the one-band image together, and then
the two n-band images are operated upon.

In the same way, for operations that take an array constant, such as
[method@Image.remainder_const], you can mix single-element arrays or
single-band images freely.

Arithmetic operations try to preserve precision by increasing the number of
bits in the output image when necessary. Generally, this follows the ANSI C
conventions for type promotion, so multiplying two
[enum@Vips.BandFormat.UCHAR] images together, for example, produces a
[enum@Vips.BandFormat.USHORT] image, and taking the [method@Image.cos] of a
[enum@Vips.BandFormat.USHORT] image produces [enum@Vips.BandFormat.FLOAT]
image.

After processing, use [method@Image.cast] and friends to take then format
back down again.[method@Image.cast_uchar], for example, will cast any image
down to 8-bit unsigned.

Images have an interpretation: a meaning for the pixel values. With
[enum@Vips.Interpretation.SRGB], for example, the first three bands will be
interpreted (for example, by a saver like [method@Image.jpegsave]) as R, G
and B, with values in 0 - 255, and any fourth band will be interpreted as an
alpha channel.

After arithmetic, you may wish to change the interpretation (for example to
save as 16-bit PNG). Use [method@Image.copy] to change the interpretation
without changing pixels.

For binary arithmetic operations, type promotion occurs in two stages.
First, the two input images are cast up to the smallest common format,
that is, the type with the smallest range that can represent the full
range of both inputs. This conversion can be represented as a table:

## Smallest common format

| **@in2/@in1**  | **uchar**      | **char**       | **ushort**     | **short**      | **uint**       | **int**        | **float**      | **double**     | **complex**    | **double complex** |
|----------------|----------------|----------------|----------------|----------------|----------------|----------------|----------------|----------------|----------------|--------------------|
| uchar          | ushort         | short          | ushort         | short          | uint           | int            | float          | double         | complex        | double complex     |
| char           | short          | short          | short          | short          | int            | int            | float          | double         | complex        | double complex     |
| ushort         | ushort         | short          | ushort         | short          | uint           | int            | float          | double         | complex        | double complex     |
| short          | short          | short          | short          | short          | int            | int            | float          | double         | complex        | double complex     |
| uint           | uint           | int            | uint           | int            | uint           | int            | float          | double         | complex        | double complex     |
| int            | int            | int            | int            | int            | int            | int            | float          | double         | complex        | double complex     |
| float          | float          | float          | float          | float          | float          | float          | float          | double         | complex        | double complex     |
| double         | double         | double         | double         | double         | double         | double         | double         | double         | double complex | double complex     |
| complex        | complex        | complex        | complex        | complex        | complex        | complex        | complex        | double complex | complex        | double complex     |
| double complex | double complex | double complex | double complex | double complex | double complex | double complex | double complex | double complex | double complex | double complex     |

In the second stage, the operation is performed between the two identical
types to form the output. The details vary between operations, but
generally the principle is that the output type should be large enough to
represent the whole range of possible values, except that int never becomes
float.

## Functions

* [method@Image.add]
* [func@Image.sum]
* [method@Image.subtract]
* [method@Image.multiply]
* [method@Image.divide]
* [method@Image.linear]
* [method@Image.linear1]
* [method@Image.remainder]
* [method@Image.remainder_const]
* [method@Image.remainder_const1]
* [method@Image.invert]
* [method@Image.abs]
* [method@Image.sign]
* [method@Image.clamp]
* [method@Image.maxpair]
* [method@Image.minpair]
* [method@Image.round]
* [method@Image.floor]
* [method@Image.ceil]
* [method@Image.rint]
* [method@Image.math]
* [method@Image.sin]
* [method@Image.cos]
* [method@Image.tan]
* [method@Image.asin]
* [method@Image.acos]
* [method@Image.atan]
* [method@Image.exp]
* [method@Image.exp10]
* [method@Image.log]
* [method@Image.log10]
* [method@Image.sinh]
* [method@Image.cosh]
* [method@Image.tanh]
* [method@Image.asinh]
* [method@Image.acosh]
* [method@Image.atanh]
* [method@Image.complex]
* [method@Image.polar]
* [method@Image.rect]
* [method@Image.conj]
* [method@Image.complex2]
* [method@Image.cross_phase]
* [method@Image.complexget]
* [method@Image.real]
* [method@Image.imag]
* [method@Image.complexform]
* [method@Image.relational]
* [method@Image.equal]
* [method@Image.notequal]
* [method@Image.less]
* [method@Image.lesseq]
* [method@Image.more]
* [method@Image.moreeq]
* [method@Image.relational_const]
* [method@Image.equal_const]
* [method@Image.notequal_const]
* [method@Image.less_const]
* [method@Image.lesseq_const]
* [method@Image.more_const]
* [method@Image.moreeq_const]
* [method@Image.relational_const1]
* [method@Image.equal_const1]
* [method@Image.notequal_const1]
* [method@Image.less_const1]
* [method@Image.lesseq_const1]
* [method@Image.more_const1]
* [method@Image.moreeq_const1]
* [method@Image.boolean]
* [method@Image.andimage]
* [method@Image.orimage]
* [method@Image.eorimage]
* [method@Image.lshift]
* [method@Image.rshift]
* [method@Image.boolean_const]
* [method@Image.andimage_const]
* [method@Image.orimage_const]
* [method@Image.eorimage_const]
* [method@Image.lshift_const]
* [method@Image.rshift_const]
* [method@Image.boolean_const1]
* [method@Image.andimage_const1]
* [method@Image.orimage_const1]
* [method@Image.eorimage_const1]
* [method@Image.lshift_const1]
* [method@Image.rshift_const1]
* [method@Image.math2]
* [method@Image.pow]
* [method@Image.wop]
* [method@Image.atan2]
* [method@Image.math2_const]
* [method@Image.pow_const]
* [method@Image.wop_const]
* [method@Image.atan2_const]
* [method@Image.math2_const1]
* [method@Image.pow_const1]
* [method@Image.wop_const1]
* [method@Image.atan2_const1]
* [method@Image.avg]
* [method@Image.deviate]
* [method@Image.min]
* [method@Image.max]
* [method@Image.stats]
* [method@Image.measure]
* [method@Image.find_trim]
* [method@Image.getpoint]
* [method@Image.hist_find]
* [method@Image.hist_find_ndim]
* [method@Image.hist_find_indexed]
* [method@Image.hough_line]
* [method@Image.hough_circle]
* [method@Image.project]
* [method@Image.profile]

## Enumerations

* [enum@OperationMath]
* [enum@OperationMath2]
* [enum@OperationRound]
* [enum@OperationRelational]
* [enum@OperationBoolean]
* [enum@OperationComplex]
* [enum@OperationComplex2]
* [enum@OperationComplexget]
