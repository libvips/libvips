/* compat stuff for vips7
 * 
 * 4/3/11
 * 	- hacked up 
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>
#include <vips/vector.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Just for compatibility. New code should use vips_object_local() directly.
 */
VipsImage *
im_open_local( VipsImage *parent, 
	const char *filename, const char *mode )
{
	VipsImage *image;

	if( !(image = vips_image_new_from_file( filename, mode )) )
		return( NULL );
	vips_object_local( parent, image );

	return( image );
}

/* Just for compatibility. New code should use vips_image_new_array().
 */
int
im_open_local_array( VipsImage *parent, 
	VipsImage **images, int n,
	const char *filename, const char *mode )
{
	int i;

	for( i = 0; i < n; i++ )
		if( !(images[i] = im_open_local( parent, filename, mode )) )
			return( -1 );

	return( 0 );
}

typedef struct {
	im_callback_fn fn;
	void *a;
	void *b;
} Callback;

static void
im_add_callback_cb( VipsImage *im, Callback *callback )
{
	if( callback->fn( callback->a, callback->b ) )
		vips_image_set_kill( im, TRUE );
}

int 
im_add_callback( VipsImage *im, 
	const char *name, im_callback_fn fn, void *a, void *b )
{
	Callback *callback;

	if( !(callback = VIPS_NEW( im, Callback )) )
		return( -1 );
	callback->fn = fn;
	callback->a = a;
	callback->b = b;
	g_signal_connect( im, name,
		G_CALLBACK( im_add_callback_cb ), callback );

	return( 0 );
}

static void
im_add_callback_cb1( VipsImage *im, void *x, Callback *callback )
{
	if( callback->fn( callback->a, callback->b ) )
		vips_image_set_kill( im, TRUE );
}

int 
im_add_callback1( VipsImage *im, 
	const char *name, im_callback_fn fn, void *a, void *b )
{
	Callback *callback;

	if( !(callback = VIPS_NEW( im, Callback )) )
		return( -1 );
	callback->fn = fn;
	callback->a = a;
	callback->b = b;
	g_signal_connect( im, name,
		G_CALLBACK( im_add_callback_cb1 ), callback );

	return( 0 );
}

/* Make something local to an image descriptor ... pass in a constructor
 * and a destructor, plus three args.
 */
void *
im_local( IMAGE *im, 
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c )
{
	void *obj;

	if( !im ) {
		im_error( "im_local", "%s", _( "NULL image descriptor" ) );
		return( NULL );
	}

        if( !(obj = cons( a, b, c )) )
                return( NULL );
        if( im_add_close_callback( im, (im_callback_fn) dest, obj, a ) ) {
                dest( obj, a );
                return( NULL );
        }
 
        return( obj );
}

/* Make an array of things local to a descriptor ... eg. make 6 local temp
 * images.
 */
int
im_local_array( IMAGE *im, void **out, int n,
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c )
{
	int i;

	for( i = 0; i < n; i++ )
		if( !(out[i] = im_local( im, cons, dest, a, b, c )) )
			return( -1 );

	return( 0 );
}

int
im_close( VipsImage *im )
{
	g_object_unref( im );

	return( 0 );
}

/* edvips.c needs this
 */
VipsImage *
im_init( const char *filename )
{
	VipsImage *image;

	image = vips_image_new( "p" );
	VIPS_SETSTR( image->filename, filename );

	return( image );
}

/* Prettyprint various header fields. Just for vips7 compat, use
 * VIPS_ENUM_VALUE() instead.
 */
const char *im_Type2char( VipsInterpretation type ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_INTERPRETATION, type ) ); }
const char *im_BandFmt2char( VipsBandFormat format ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_BAND_FORMAT, format ) ); }
const char *im_Coding2char( VipsCoding coding ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_CODING, coding ) ); }
const char *im_dtype2char( VipsImageType n ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_IMAGE_TYPE, n ) ); }
const char *im_dhint2char( VipsDemandStyle style ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_DEMAND_STYLE, style ) ); }

VipsInterpretation im_char2Type( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_INTERPRETATION, str ) ); }
VipsBandFormat im_char2BandFmt( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_BAND_FORMAT, str ) ); }
VipsCoding im_char2Coding( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_CODING, str ) ); }
VipsImageType im_char2dtype( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_IMAGE_TYPE, str ) ); }
VipsDemandStyle im_char2dhint( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_DEMAND_STYLE, str ) ); }

/* Totally useless now.
 */
const char *im_Compression2char( int n ) { return( "NONE" ); }
int im_char2Compression( const char *str ) { return( -1 ); }

/* Wrap one / many is being replaced by a class thing.
 */

typedef struct {
	im_wrapmany_fn fn;	/* Function we call */ 
	void *a, *b;		/* User values for function */
} Bundle;

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

/* Convert a VipsRegion.
 */
static int
process_region( VipsRegion *or, void *seq, void *a, void *b )
{
	VipsRegion **ir = (VipsRegion **) seq;
	Bundle *bun = (Bundle *) b;

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

	/* Convert linewise.
	 */
	for( y = 0; y < or->valid.height; y++ ) {
		PEL *p1[MAX_INPUT_IMAGES];

		/* Make a copy of p[] which the buffer function can mess up if
		 * it wants.
		 */
		for( i = 0; ir[i]; i++ )
			p1[i] = p[i];

		/* Bizarre double-cast stops a bogus gcc 4.1 compiler warning.
		 */
		bun->fn( (void **) ((void *)p1), q, 
			or->valid.width, bun->a, bun->b );

		/* Move pointers on.
		 */
		for( i = 0; ir[i]; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	return( 0 );
}

/* Make a copy of an array of input images.
 */
static IMAGE **
dupims( IMAGE *out, IMAGE **in )
{
	IMAGE **new;
	int i, n;

	/* Count input images.
	 */
	for( n = 0; in[n]; n++ )
		;

	/* Allocate new array.
	 */
	if( !(new = VIPS_ARRAY( out, n + 1, IMAGE * )) )
		return( NULL );
	
	/* Copy.
	 */
	for( i = 0; i < n; i++ )
		new[i] = in[i];
	new[n] = NULL;

	return( new );
}

/**
 * im_wrapmany_fn:
 * @in: %NULL-terminated array of input buffers
 * @out: write processed pixels here
 * @width: number of pixels in buffer
 * @a: user data
 * @b: user data
 *
 * Given an array of buffers of input pixels, write a buffer of output pixels.
 */

/**
 * im_wrapmany:
 * @in: %NULL-terminated array of input images
 * @out: image to generate
 * @fn: buffer-processing function
 * @a: user data
 * @b: user data
 *
 * Wrap-up a buffer processing function as a PIO VIPS function.
 *
 * Given a NULL-terminated list of input images all of the same size, an
 * output image and a buffer processing function, make a PIO image processing
 * operation.
 *
 * See also: im_wrapone(), im_wraptwo(), vips_image_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_wrapmany( IMAGE **in, IMAGE *out, im_wrapmany_fn fn, void *a, void *b )
{
	Bundle *bun = VIPS_NEW( out, Bundle );
	int i, n;

	/* Count input images.
	 */
	for( n = 0; in[n]; n++ )
		;
	if( n >= MAX_INPUT_IMAGES - 1 ) {
		vips_error( "im_wrapmany", "%s", _( "too many input images" ) );
		return( -1 );
	}

	/* Save args.
	 */
	if( !bun || !(in = dupims( out, in )) )
		return( -1 );
	bun->fn = fn;
	bun->a = a;
	bun->b = b;

	/* Check descriptors --- make sure that our caller has done this
	 * correctly.
	 */
	for( i = 0; i < n; i++ ) {
		if( in[i]->Xsize != out->Xsize || in[i]->Ysize != out->Ysize ) {
			vips_error( "im_wrapmany", 
				"%s", _( "descriptors differ in size" ) );
			return( -1 );
		}

		/* Check io style.
		 */
		if( vips_image_pio_input( in[i] ) )
			return( -1 );
	}
	if( vips_image_pio_output( out ) )
		return( -1 );

	/* Hint demand style. Being a buffer processor, we are happiest with
	 * thin strips.
	 */
        if( vips_demand_hint_array( out, VIPS_DEMAND_STYLE_THINSTRIP, in ) )
                return( -1 );

	/* Generate!
	 */
	if( vips_image_generate( out,
		vips_start_many, process_region, vips_stop_many, in, bun ) )
		return( -1 );

	return( 0 );
}

static void
wrapone_gen( void **ins, void *out, int width, Bundle *bun, void *dummy )
{
	((im_wrapone_fn) (bun->fn)) (ins[0], out, width, bun->a, bun->b );
}

/**
 * im_wrapone_fn:
 * @in: input pixels
 * @out: write processed pixels here
 * @width: number of pixels in buffer
 * @a: user data
 * @b: user data
 *
 * Given a buffer of input pixels, write a buffer of output pixels.
 */

/**
 * im_wrapone:
 * @in: input image
 * @out: image to generate
 * @fn: buffer-processing function
 * @a: user data
 * @b: user data
 *
 * Wrap-up a buffer processing function as a PIO VIPS function.
 *
 * Given an input image, an
 * output image and a buffer processing function, make a PIO image processing
 * operation.
 *
 * See also: im_wrapmany(), im_wraptwo(), vips_image_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_wrapone( IMAGE *in, IMAGE *out, im_wrapone_fn fn, void *a, void *b )
{
	Bundle *bun = VIPS_NEW( out, Bundle );
	IMAGE *invec[2];

	/* Heh, yuk. We cast back above.
	 */
	bun->fn = (im_wrapmany_fn) fn;
	bun->a = a;
	bun->b = b;
	invec[0] = in; invec[1] = NULL;

	return( im_wrapmany( invec, out, 
		(im_wrapmany_fn) wrapone_gen, bun, NULL ) );
}

static void
wraptwo_gen( void **ins, void *out, int width, Bundle *bun, void *dummy )
{
	((im_wraptwo_fn) (bun->fn)) (ins[0], ins[1], out, 
		width, bun->a, bun->b );
}

/**
 * im_wraptwo_fn:
 * @in1: input pixels from image 1
 * @in2: input pixels from image 2
 * @out: write processed pixels here
 * @width: number of pixels in buffer
 * @a: user data
 * @b: user data
 *
 * Given a pair of buffers of input pixels, write a buffer of output pixels.
 */

/**
 * im_wraptwo:
 * @in1: first input image
 * @in2: second input image
 * @out: image to generate
 * @fn: buffer-processing function
 * @a: user data
 * @b: user data
 *
 * Wrap-up a buffer processing function as a PIO VIPS function.
 *
 * Given a pair of input images of the same size, an
 * output image and a buffer processing function, make a PIO image processing
 * operation.
 *
 * See also: im_wrapone(), im_wrapmany(), vips_image_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_wraptwo( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	im_wraptwo_fn fn, void *a, void *b )
{
	Bundle *bun = VIPS_NEW( out, Bundle );
	IMAGE *invec[3];

	bun->fn = (im_wrapmany_fn) fn;
	bun->a = a;
	bun->b = b;
	invec[0] = in1; invec[1] = in2; invec[2] = NULL;

	return( im_wrapmany( invec, out, 
		(im_wrapmany_fn) wraptwo_gen, bun, NULL ) );
}

/* Save a bit of typing.
 */
#define UC IM_BANDFMT_UCHAR
#define C IM_BANDFMT_CHAR
#define US IM_BANDFMT_USHORT
#define S IM_BANDFMT_SHORT
#define UI IM_BANDFMT_UINT
#define I IM_BANDFMT_INT
#define F IM_BANDFMT_FLOAT
#define X IM_BANDFMT_COMPLEX
#define D IM_BANDFMT_DOUBLE
#define DX IM_BANDFMT_DPCOMPLEX

/* For two integer types, the "largest", ie. one which can represent the
 * full range of both.
 */
static int bandfmt_largest[6][6] = {
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
static VipsBandFmt
im__format_common( VipsBandFmt in1, VipsBandFmt in2 )
{
	if( vips_bandfmt_iscomplex( in1 ) || 
		vips_bandfmt_iscomplex( in2 ) ) {
		/* What kind of complex?
		 */
		if( in1 == IM_BANDFMT_DPCOMPLEX || in2 == IM_BANDFMT_DPCOMPLEX )
			/* Output will be DPCOMPLEX. 
			 */
			return( IM_BANDFMT_DPCOMPLEX );
		else
			return( IM_BANDFMT_COMPLEX );

	}
	else if( vips_bandfmt_isfloat( in1 ) || 
		vips_bandfmt_isfloat( in2 ) ) {
		/* What kind of float?
		 */
		if( in1 == IM_BANDFMT_DOUBLE || in2 == IM_BANDFMT_DOUBLE )
			return( IM_BANDFMT_DOUBLE );
		else
			return( IM_BANDFMT_FLOAT );
	}
	else 
		/* Must be int+int -> int.
		 */
		return( bandfmt_largest[in1][in2] );
}

int
im__formatalike_vec( IMAGE **in, IMAGE **out, int n )
{
	int i;
	VipsBandFmt fmt;

	g_assert( n >= 1 );

	fmt = in[0]->BandFmt;
	for( i = 1; i < n; i++ )
		fmt = im__format_common( fmt, in[i]->BandFmt );

	for( i = 0; i < n; i++ )
		if( im_clip2fmt( in[i], out[i], fmt ) )
			return( -1 );

	return( 0 );
}

int
im__formatalike( IMAGE *in1, IMAGE *in2, IMAGE *out1, IMAGE *out2 )
{
	IMAGE *in[2];
	IMAGE *out[2];

	in[0] = in1;
	in[1] = in2;
	out[0] = out1;
	out[1] = out2;

	return( im__formatalike_vec( in, out, 2 ) );
}

/* Make an n-band image. Input 1 or n bands.
 */
int
im__bandup( const char *domain, IMAGE *in, IMAGE *out, int n )
{
	IMAGE *bands[256];
	int i;

	if( in->Bands == n ) 
		return( im_copy( in, out ) );
	if( in->Bands != 1 ) {
		im_error( domain, _( "not one band or %d bands" ), n );
		return( -1 );
	}
	if( n > 256 || n < 1 ) {
		im_error( domain, "%s", _( "bad bands" ) );
		return( -1 );
	}

	for( i = 0; i < n; i++ )
		bands[i] = in;

	return( im_gbandjoin( bands, out, n ) );
}

int
im__bandalike_vec( const char *domain, IMAGE **in, IMAGE **out, int n )
{
	int i;
	int max_bands;

	g_assert( n >= 1 );

	max_bands = in[0]->Bands;
	for( i = 1; i < n; i++ )
		max_bands = IM_MAX( max_bands, in[i]->Bands );
	for( i = 0; i < n; i++ )
		if( im__bandup( domain, in[i], out[i], max_bands ) )
			return( -1 );

	return( 0 );
}

int
im__bandalike( const char *domain, 
	IMAGE *in1, IMAGE *in2, IMAGE *out1, IMAGE *out2 )
{
	IMAGE *in[2];
	IMAGE *out[2];

	in[0] = in1;
	in[1] = in2;
	out[0] = out1;
	out[1] = out2;
	if( im__bandalike_vec( domain, in, out, 2 ) )
		return( -1 );

	return( 0 );
}

int
im__sizealike_vec( VipsImage **in, VipsImage **out, int n )
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
		if( im_embed( in[i], out[i], 0, 0, 0, width_max, height_max ) )
			return( -1 );

	return( 0 );
}

int
im__sizealike( VipsImage *in1, VipsImage *in2, 
	VipsImage *out1, VipsImage *out2 )
{
	IMAGE *in[2];
	IMAGE *out[2];

	in[0] = in1;
	in[1] = in2;
	out[0] = out1;
	out[1] = out2;

	return( im__sizealike_vec( in, out, 2 ) );
}

/* The common part of most binary arithmetic, relational and boolean
 * operators. We:
 *
 * - check in and out
 * - cast in1 and in2 up to a common format
 * - cast the common format to the output format with the supplied table
 * - equalise bands 
 * - equalise size 
 * - run the supplied buffer operation passing one of the up-banded,
 *   up-casted and up-sized inputs as the first param
 */
int
im__arith_binary( const char *domain, 
	IMAGE *in1, IMAGE *in2, IMAGE *out, 
	int format_table[10], 
	im_wrapmany_fn fn, void *b )
{
	IMAGE *t[7];

	if( im_piocheck( in1, out ) || 
		im_pincheck( in2 ) ||
		im_check_bands_1orn( domain, in1, in2 ) ||
		im_check_uncoded( domain, in1 ) ||
		im_check_uncoded( domain, in2 ) )
		return( -1 );

	/* Cast our input images up to a common format and bands.
	 */
	if( im_open_local_array( out, t, 6, domain, "p" ) ||
		im__formatalike( in1, in2, t[0], t[1] ) ||
		im__bandalike( domain, t[0], t[1], t[2], t[3] ) ||
		im__sizealike( t[2], t[3], t[4], t[5] ) )
		return( -1 );

	/* Generate the output.
	 */
	if( im_cp_descv( out, t[4], t[5], NULL ) )
		return( -1 );

	/* What number of bands will we write? Same as up-banded input.
	 */
	out->Bands = t[4]->Bands;

	/* What output type will we write? 
	 */
	out->BandFmt = format_table[t[4]->BandFmt];

	/* And process! The buffer function gets one of the input images as a
	 * sample.
	 */
	t[6] = NULL;
	if( im_wrapmany( t + 4, out, fn, t[4], b ) )	
		return( -1 );

	return( 0 );
}

VipsVector *
im__init_program( VipsVector *vectors[IM_BANDFMT_LAST], 
	VipsBandFmt format_table[IM_BANDFMT_LAST], VipsBandFmt fmt )
{
	int isize = im__sizeof_bandfmt[fmt];
	int osize = im__sizeof_bandfmt[format_table[fmt]];

	VipsVector *v;

	v = vips_vector_new( "binary arith", osize );

	vips_vector_source_name( v, "s1", isize );
	vips_vector_source_name( v, "s2", isize );
	vips_vector_temporary( v, "t1", osize );
	vips_vector_temporary( v, "t2", osize );

	vectors[fmt] = v;

	return( v );
}

void
im__compile_programs( VipsVector *vectors[IM_BANDFMT_LAST] )
{
	int fmt;

	for( fmt = 0; fmt < IM_BANDFMT_LAST; fmt++ ) {
		if( vectors[fmt] &&
			!vips_vector_compile( vectors[fmt] ) )
			IM_FREEF( vips_vector_free, vectors[fmt] );
	}

#ifdef DEBUG
	printf( "im__compile_programs: " );
	for( fmt = 0; fmt < IM_BANDFMT_LAST; fmt++ ) 
		if( vectors[fmt] )
			printf( "%s ", im_BandFmt2char( fmt ) );
	printf( "\n" );
#endif /*DEBUG*/
}

int 
im_add( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips_call( "add", in1, in2, out, NULL ) );
}
