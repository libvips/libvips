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

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include "arithmetic.h"

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
		im_error( domain, "%s", _( "bad bands" ) );
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
	IMAGE *in[2];
	IMAGE *out[2];

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
	IMAGE *in[2];
	IMAGE *out[2];

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

	PEL *p[MAX_INPUT_IMAGES], *q;
	int i, y;

	/* Prepare all input regions and make buffer pointers.
	 */
	for( i = 0; ir[i]; i++ ) {
		if( vips_region_prepare( ir[i], &or->valid ) ) 
			return( -1 );
		p[i] = (PEL *) VIPS_REGION_ADDR( ir[i], 
			or->valid.left, or->valid.top );
	}
	p[i] = NULL;
	q = (PEL *) VIPS_REGION_ADDR( or, or->valid.left, or->valid.top );

	for( y = 0; y < or->valid.height; y++ ) {
		class->process_line( arithmetic, q, p, or->valid.width );

		for( i = 0; ir[i]; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	return( 0 );
}

static int
vips_arithmetic_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_GET_CLASS( arithmetic );

	VipsImage **format;
	VipsImage **band;
	VipsImage **size;
	int i;

#ifdef DEBUG
	printf( "vips_arithmetic_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_set( arithmetic, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_arithmetic_parent_class )->build( object ) )
		return( -1 );

	/* No need to check input bands, bandalike will do this for us.
	 */
	if( arithmetic->n > MAX_INPUT_IMAGES ) {
		vips_error( "VipsArithmetic",
			"%s", _( "too many input images" ) );
		return( -1 );
	}
	for( i = 0; i < arithmetic->n; i++ )
		if( vips_image_pio_input( arithmetic->in[i] ) || 
			vips_check_uncoded( "VipsArithmetic", 
				arithmetic->in[i] ) )
			return( -1 );
	if( vips_image_pio_output( arithmetic->out ) )
		return( -1 );

	format = (VipsImage **) 
		vips_object_local_array( object, arithmetic->n );
	band = (VipsImage **) 
		vips_object_local_array( object, arithmetic->n );
	size = (VipsImage **) 
		vips_object_local_array( object, arithmetic->n );

	/* Cast our input images up to a common format, bands and size.
	 */
	if( vips__formatalike_vec( arithmetic->in, format, arithmetic->n ) ||
		vips__bandalike_vec( "VipsArithmetic", 
			format, band, arithmetic->n, arithmetic->base_bands ) ||
		vips__sizealike_vec( band, size, arithmetic->n ) )
		return( -1 );

	/* Keep a copy of the processed images here for subclasses.
	 */
	arithmetic->ready = size;

	if( vips_image_copy_fields_array( arithmetic->out, size ) )
		return( -1 );
        vips_demand_hint_array( arithmetic->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, size );

	arithmetic->out->Bands = size[0]->Bands;
	arithmetic->out->BandFmt = aclass->format_table[size[0]->BandFmt];

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

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "arithmetic";
	vobject_class->description = _( "arithmetic operations" );
	vobject_class->build = vips_arithmetic_build;

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

	if( !vips_vector_get_enabled() ||
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
	for( i = 0; i < IM_BANDFMT_LAST; i++ ) 
		if( class->vector_program[i] )
			printf( "%s ", 
				VIPS_ENUM_NICK( VIPS_TYPE_BAND_FORMAT, i ) );
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
	extern GType vips_measure_get_type( void ); 
	extern GType vips_recomb_get_type( void ); 
	extern GType vips_round_get_type( void ); 
	extern GType vips_relational_get_type( void ); 
	extern GType vips_relational_const_get_type( void ); 
	extern GType vips_remainder_get_type( void ); 
	extern GType vips_remainder_const_get_type( void ); 
	extern GType vips_boolean_get_type( void ); 
	extern GType vips_boolean_const_get_type( void ); 
	extern GType vips_math2_get_type( void ); 
	extern GType vips_math2_const_get_type( void ); 

	vips_add_get_type();
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
	vips_measure_get_type();
	vips_recomb_get_type();
	vips_round_get_type();
	vips_relational_get_type();
	vips_relational_const_get_type(); 
	vips_remainder_get_type();
	vips_remainder_const_get_type(); 
	vips_boolean_get_type(); 
	vips_boolean_const_get_type(); 
	vips_math2_get_type(); 
	vips_math2_const_get_type(); 
}
