/* base class for all arithmetic operations
 *
 * properties:
 * 	- one output image, one or more inputs
 * 	- cast input images to match
 * 	- output is large enough to hold output values (value preserving)
 * 	- point-to-point operations (ie. each pixel depends only on the
 * 	  corresponding pixel in the input)
 * 	- LUT-able: ie. arithmetic (image) can be exactly replaced by
 * 	  maplut (image, arithmetic (lut)) for 8/16 bit int images
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "parithmetic.h"

/** 
 * SECTION: arithmetic
 * @short_description: operations which perform pixel arithmetic, trig, log, statistics
 * @see_also: <link linkend="libvips-boolean">boolean</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations perform pixel arithmetic, that is, they perform an
 * arithmetic operation, such as addition, on every pixel in an image or a
 * pair of images. All (except in a few cases noted below) will work with 
 * images of any type or any mixture of types, of any size and of any number 
 * of bands.
 *
 * For binary operations, if the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * In the same way, for operations that take an array constant, such as 
 * vips_remainder_const(), you can mix single-element arrays or single-band 
 * images freely.
 *
 * Arithmetic operations try to preserve precision by increasing the number of
 * bits in the output image when necessary. Generally, this follows the ANSI C
 * conventions for type promotion, so multiplying two
 * #VIPS_FORMAT_UCHAR images together, for example, produces a 
 * #VIPS_FORMAT_USHORT image, and taking the im_costra() of a 
 * #VIPS_FORMAT_USHORT image produces #VIPS_FORMAT_FLOAT image. 
 *
 * For binary arithmetic operations, type promotion occurs in two stages. 
 * First, the two input images are cast up to the smallest common format, 
 * that is, the type with the smallest range that can represent the full 
 * range of both inputs. This conversion can be represented as a table:
 *
 * <table>
 *   <title>Smallest common format</title>
 *   <tgroup cols='10' align='left' colsep='1' rowsep='1'>
 *     <thead>
 *       <row>
 *         <entry>@in2/@in1</entry>
 *         <entry>uchar</entry>
 *         <entry>char</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *     </thead>
 *     <tbody>
 *       <row>
 *         <entry>uchar</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>char</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>ushort</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>uint</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *     </tbody>
 *   </tgroup>
 * </table>
 *
 * In the second stage, the operation is performed between the two identical 
 * types to form the output. The details vary between operations, but 
 * generally the principle is that the output type should be large enough to 
 * represent the whole range of possible values, except that int never becomes 
 * float.
 */

G_DEFINE_ABSTRACT_TYPE( VipsArithmetic, vips_arithmetic, VIPS_TYPE_OPERATION );

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* For two integer types, the "largest", ie. one which can represent the
 * full range of both.
 */
static VipsBandFormat format_largest[6][6] = {
        /* UC  C   US  S   UI  I */
/* UC */ { UC, S,  US, S,  UI, I },
/* C */  { S,  C,  I,  S,  I,  I },
/* US */ { US, I,  US, I,  UI, I },
/* S */  { S,  S,  I,  S,  I,  I },
/* UI */ { UI, I,  UI, I,  UI, I },
/* I */  { I,  I,  I,  I,  I,  I }
};

/* For two formats, find one which can represent the full range of both.
 */
static VipsBandFormat
vips_format_common( VipsBandFormat a, VipsBandFormat b )
{
	if( vips_band_format_iscomplex( a ) || 
		vips_band_format_iscomplex( b ) ) {
		if( a == VIPS_FORMAT_DPCOMPLEX || 
			b == VIPS_FORMAT_DPCOMPLEX )
			return( VIPS_FORMAT_DPCOMPLEX );
		else
			return( VIPS_FORMAT_COMPLEX );

	}
	else if( vips_band_format_isfloat( a ) || 
		vips_band_format_isfloat( b ) ) {
		if( a == VIPS_FORMAT_DOUBLE || 
			b == VIPS_FORMAT_DOUBLE )
			return( VIPS_FORMAT_DOUBLE );
		else
			return( VIPS_FORMAT_FLOAT );
	}
	else 
		return( format_largest[a][b] );
}

int
vips__formatalike_vec( VipsImage **in, VipsImage **out, int n )
{
	int i;
	VipsBandFormat format;

	g_assert( n >= 1 );

	format = in[0]->BandFmt;
	for( i = 1; i < n; i++ )
		format = vips_format_common( format, in[i]->BandFmt );

	for( i = 0; i < n; i++ )
		if( vips_cast( in[i], &out[i], format, NULL ) )
			return( -1 );

	return( 0 );
}

int
vips__sizealike_vec( VipsImage **in, VipsImage **out, int n )
{
	int i;
	int width_max;
	int height_max;

	g_assert( n >= 1 );

	width_max = in[0]->Xsize;
	height_max = in[0]->Ysize;
	for( i = 1; i < n; i++ ) {
		width_max = VIPS_MAX( width_max, in[i]->Xsize );
		height_max = VIPS_MAX( height_max, in[i]->Ysize );
	}

	for( i = 0; i < n; i++ )
		if( vips_embed( in[i], &out[i], 
			0, 0, width_max, height_max, NULL ) )
			return( -1 );

	return( 0 );
}

/* Make an n-band image. Input 1 or n bands.
 */
int
vips__bandup( const char *domain, VipsImage *in, VipsImage **out, int n )
{
	VipsImage *bands[256];
	int i;

	if( in->Bands == n ) 
		return( vips_copy( in, out, NULL ) );
	if( in->Bands != 1 ) {
		vips_error( domain, _( "not one band or %d bands" ), n );
		return( -1 );
	}
	if( n > 256 || n < 1 ) {
		vips_error( domain, "%s", _( "bad bands" ) );
		return( -1 );
	}

	for( i = 0; i < n; i++ )
		bands[i] = in;

	return( vips_bandjoin( bands, out, n, NULL ) );
}

/* base_bands is the default minimum. 
 *
 * Handy for example, if you have VipsLinear with
 * a 3-element vector of constants and a 1-band input image, you need to cast
 * the image up to three bands.
 */
int
vips__bandalike_vec( const char *domain, 
	VipsImage **in, VipsImage **out, int n, int base_bands )
{
	int i;
	int max_bands;

	g_assert( n >= 1 );

	max_bands = base_bands;
	for( i = 0; i < n; i++ )
		max_bands = VIPS_MAX( max_bands, in[i]->Bands );
	for( i = 0; i < n; i++ )
		if( vips__bandup( domain, in[i], &out[i], max_bands ) )
			return( -1 );

	return( 0 );
}

int
vips__formatalike( VipsImage *in1, VipsImage *in2, 
	VipsImage **out1, VipsImage **out2 )
{
	VipsImage *in[2];
	VipsImage *out[2];

	in[0] = in1;
	in[1] = in2;

	if( vips__formatalike_vec( in, out, 2 ) )
		return( -1 );

	*out1 = out[0];
	*out2 = out[1];

	return( 0 );
}

int
vips__sizealike( VipsImage *in1, VipsImage *in2, 
	VipsImage **out1, VipsImage **out2 )
{
	VipsImage *in[2];
	VipsImage *out[2];

	in[0] = in1;
	in[1] = in2;

	if( vips__sizealike_vec( in, out, 2 ) )
		return( -1 );

	*out1 = out[0];
	*out2 = out[1];

	return( 0 );
}

int
vips__bandalike( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage **out1, VipsImage **out2 )
{
	VipsImage *in[2];
	VipsImage *out[2];

	in[0] = in1;
	in[1] = in2;

	if( vips__bandalike_vec( domain, in, out, 2, 1 ) )
		return( -1 );

	*out1 = out[0];
	*out2 = out[1];

	return( 0 );
}

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

static int
vips_arithmetic_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( b ); 
	VipsArithmeticClass *class = VIPS_ARITHMETIC_GET_CLASS( arithmetic ); 
	Rect *r = &or->valid;

	VipsPel *p[MAX_INPUT_IMAGES], *q;
	int i, y;

	/* Prepare all input regions and make buffer pointers.
	 */
	for( i = 0; ir[i]; i++ ) {
		if( vips_region_prepare( ir[i], r ) ) 
			return( -1 );
		p[i] = (VipsPel *) VIPS_REGION_ADDR( ir[i], r->left, r->top );
	}
	p[i] = NULL;
	q = (VipsPel *) VIPS_REGION_ADDR( or, r->left, r->top );

	VIPS_GATE_START( "vips_arithmetic_gen: work" );

	for( y = 0; y < r->height; y++ ) {
		class->process_line( arithmetic, q, p, r->width );

		for( i = 0; ir[i]; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	VIPS_GATE_STOP( "vips_arithmetic_gen: work" );

	return( 0 );
}

static int
vips_arithmetic_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_GET_CLASS( arithmetic );

	VipsImage **decode;
	VipsImage **format;
	VipsImage **band;
	VipsImage **size;
	int i;

#ifdef DEBUG
	printf( "vips_arithmetic_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_arithmetic_parent_class )->
		build( object ) ) 
		return( -1 );

	g_object_set( arithmetic, "out", vips_image_new(), NULL ); 

	/* No need to check input bands, bandalike will do this for us.
	 */
	if( arithmetic->n > MAX_INPUT_IMAGES ) {
		vips_error( class->nickname,
			"%s", _( "too many input images" ) );
		return( -1 );
	}

	decode = (VipsImage **) 
		vips_object_local_array( object, arithmetic->n );
	format = (VipsImage **) 
		vips_object_local_array( object, arithmetic->n );
	band = (VipsImage **) 
		vips_object_local_array( object, arithmetic->n );
	size = (VipsImage **) 
		vips_object_local_array( object, arithmetic->n );

	/* Decode RAD/LABQ etc.
	 */
	for( i = 0; i < arithmetic->n; i++ )
		if( vips_image_decode( arithmetic->in[i], &decode[i] ) )
			return( -1 );

	/* Cast our input images up to a common format, bands and size.
	 */
	if( vips__formatalike_vec( decode, format, arithmetic->n ) ||
		vips__bandalike_vec( class->nickname, 
			format, band, arithmetic->n, arithmetic->base_bands ) ||
		vips__sizealike_vec( band, size, arithmetic->n ) ) 
		return( -1 );

	/* Keep a copy of the processed images here for subclasses.
	 */
	arithmetic->ready = size;

	if( vips_image_pipeline_array( arithmetic->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, arithmetic->ready ) ) 
		return( -1 );

	arithmetic->out->Bands = arithmetic->ready[0]->Bands;
	if( arithmetic->format != VIPS_FORMAT_NOTSET )
		arithmetic->out->BandFmt = arithmetic->format;
	else
		arithmetic->out->BandFmt = 
			aclass->format_table[arithmetic->ready[0]->BandFmt];

	if( vips_image_generate( arithmetic->out,
		vips_start_many, vips_arithmetic_gen, vips_stop_many, 
		arithmetic->ready, arithmetic ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_arithmetic_class_init( VipsArithmeticClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "arithmetic";
	vobject_class->description = _( "arithmetic operations" );
	vobject_class->build = vips_arithmetic_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsArithmetic, out ) );
}

static void
vips_arithmetic_init( VipsArithmetic *arithmetic )
{
	arithmetic->base_bands = 1;
	arithmetic->format = VIPS_FORMAT_NOTSET;
}

void 
vips_arithmetic_set_format_table( VipsArithmeticClass *class, 
	const VipsBandFormat *format_table )
{
	int i;

	g_assert( !class->format_table );

	class->format_table = format_table;

	for( i = 0; i < VIPS_FORMAT_LAST; i++ ) {
		int isize = vips_format_sizeof( i );
		int osize = vips_format_sizeof( (int) format_table[i] );

		VipsVector *v;

		v = vips_vector_new( "arithmetic", osize );

		vips_vector_source_name( v, "s1", isize );
		vips_vector_source_name( v, "s2", isize );
		vips_vector_temporary( v, "t1", osize );
		vips_vector_temporary( v, "t2", osize );

		class->vectors[i] = v;
	}
}

/* Get the stub for this program ... use _get_vector() to get the compiled
 * code.
 */
VipsVector *
vips_arithmetic_get_program( VipsArithmeticClass *class, VipsBandFormat fmt )
{
	g_assert( (int) fmt >= 0 && (int) fmt < VIPS_FORMAT_LAST );
	g_assert( !class->vector_program[fmt] );

	class->vector_program[fmt] = TRUE;

	return( class->vectors[fmt] );
}

/* Get the compiled code for this type, if available.
 */
VipsVector *
vips_arithmetic_get_vector( VipsArithmeticClass *class, VipsBandFormat fmt )
{
	g_assert( fmt >= 0 && fmt < VIPS_FORMAT_LAST );

	if( !vips_vector_isenabled() ||
		!class->vector_program[fmt] )
		return( NULL );

	return( class->vectors[fmt] );
}

void
vips_arithmetic_compile( VipsArithmeticClass *class ) 
{
	int i;

	g_assert( class->format_table );

	for( i = 0; i < VIPS_FORMAT_LAST; i++ ) 
		if( class->vector_program[i] &&
			!vips_vector_compile( class->vectors[i] ) )
			/* If compilation fails, turn off the vector for this
			 * type.
			 */
			class->vector_program[i] = FALSE;

#ifdef DEBUG
	printf( "vips_arithmetic_compile: " );
	for( i = 0; i < VIPS_FORMAT_LAST; i++ ) 
		if( class->vector_program[i] )
			printf( "%s ", 
				vips_enum_nick( VIPS_TYPE_BAND_FORMAT, i ) );
	printf( "\n" );
#endif /*DEBUG*/
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_arithmetic_operation_init( void )
{
	extern GType vips_add_get_type( void ); 
	extern GType vips_sum_get_type( void ); 
	extern GType vips_subtract_get_type( void ); 
	extern GType vips_multiply_get_type( void ); 
	extern GType vips_divide_get_type( void ); 
	extern GType vips_invert_get_type( void ); 
	extern GType vips_avg_get_type( void ); 
	extern GType vips_min_get_type( void ); 
	extern GType vips_max_get_type( void ); 
	extern GType vips_deviate_get_type( void ); 
	extern GType vips_linear_get_type( void ); 
	extern GType vips_math_get_type( void ); 
	extern GType vips_abs_get_type( void ); 
	extern GType vips_sign_get_type( void ); 
	extern GType vips_stats_get_type( void ); 
	extern GType vips_hist_find_get_type( void ); 
	extern GType vips_hist_find_ndim_get_type( void ); 
	extern GType vips_hist_find_indexed_get_type( void ); 
	extern GType vips_hough_line_get_type( void ); 
	extern GType vips_hough_circle_get_type( void ); 
	extern GType vips_project_get_type( void ); 
	extern GType vips_profile_get_type( void ); 
	extern GType vips_measure_get_type( void ); 
	extern GType vips_getpoint_get_type( void ); 
	extern GType vips_round_get_type( void ); 
	extern GType vips_relational_get_type( void ); 
	extern GType vips_relational_const_get_type( void ); 
	extern GType vips_remainder_get_type( void ); 
	extern GType vips_remainder_const_get_type( void ); 
	extern GType vips_boolean_get_type( void ); 
	extern GType vips_boolean_const_get_type( void ); 
	extern GType vips_math2_get_type( void ); 
	extern GType vips_math2_const_get_type( void ); 
	extern GType vips_complex_get_type( void ); 
	extern GType vips_complex2_get_type( void ); 
	extern GType vips_complexget_get_type( void ); 
	extern GType vips_complexform_get_type( void ); 

	vips_add_get_type();
	vips_sum_get_type();
	vips_subtract_get_type();
	vips_multiply_get_type();
	vips_divide_get_type();
	vips_invert_get_type();
	vips_avg_get_type();
	vips_min_get_type();
	vips_max_get_type();
	vips_deviate_get_type();
	vips_linear_get_type();
	vips_math_get_type();
	vips_abs_get_type();
	vips_sign_get_type();
	vips_stats_get_type();
	vips_hist_find_get_type(); 
	vips_hist_find_ndim_get_type(); 
	vips_hist_find_indexed_get_type(); 
	vips_hough_line_get_type(); 
	vips_hough_circle_get_type(); 
	vips_project_get_type(); 
	vips_profile_get_type(); 
	vips_measure_get_type();
	vips_getpoint_get_type();
	vips_round_get_type();
	vips_relational_get_type();
	vips_relational_const_get_type(); 
	vips_remainder_get_type();
	vips_remainder_const_get_type(); 
	vips_boolean_get_type(); 
	vips_boolean_const_get_type(); 
	vips_math2_get_type(); 
	vips_math2_const_get_type(); 
	vips_complex_get_type(); 
	vips_complex2_get_type(); 
	vips_complexget_get_type(); 
	vips_complexform_get_type(); 
}
