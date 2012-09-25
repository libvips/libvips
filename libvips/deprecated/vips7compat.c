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

VipsImage *
im_open( const char *filename, const char *mode )
{
	VipsImage *image;

	/* Pass in a nonsense name for argv0 ... this init path is only here
	 * for old programs which are missing an vips_init() call. We need
	 * i18n set up before we can translate.
	 */
	if( vips_init( "giant_banana" ) )
		vips_error_clear();

	/* We have to go via the old VipsFormat system so we can support the
	 * "filename:option" syntax.
	 *
	 * Use "rs" to turn on seq mode.
	 */
	if( strcmp( mode, "r" ) == 0 ||
		strcmp( mode, "rd" ) == 0 ) {
		if( !(image = vips__deprecated_open_read( filename, FALSE )) )
			return( NULL );
	}
	else if( strcmp( mode, "rs" ) == 0 ) { 
		if( !(image = vips__deprecated_open_read( filename, TRUE )) )
			return( NULL );
	}
	else if( strcmp( mode, "w" ) == 0 ) {
		if( !(image = vips__deprecated_open_write( filename )) )
			return( NULL );
	}
	else {
		if( !(image = vips_image_new_mode( filename, mode )) )
			return( NULL );
	}

	return( image );
}

/* Just for compatibility. New code should use vips_object_local() directly.
 */
VipsImage *
im_open_local( VipsImage *parent, 
	const char *filename, const char *mode )
{
	VipsImage *image;

	if( !(image = im_open( filename, mode )) )
		return( NULL );
	vips_object_local( parent, image );

	return( image );
}

/* Just for compatibility. New code should use vips_object_local_array().
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

	callback = VIPS_NEW( VIPS_OBJECT( im ), Callback );
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

	callback = VIPS_NEW( VIPS_OBJECT( im ), Callback );
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

	image = vips_image_new();
	IM_SETSTR( image->filename, filename );

	return( image );
}

/* Prettyprint various header fields. Just for vips7 compat, use
 * vips_enum_value() instead.
 */
const char *im_Type2char( VipsInterpretation type ) 
	{ return( vips_enum_string( VIPS_TYPE_INTERPRETATION, type ) ); }
const char *im_BandFmt2char( VipsBandFormat format ) 
	{ return( vips_enum_string( VIPS_TYPE_BAND_FORMAT, format ) ); }
const char *im_Coding2char( VipsCoding coding ) 
	{ return( vips_enum_string( VIPS_TYPE_CODING, coding ) ); }
const char *im_dtype2char( VipsImageType n ) 
	{ return( vips_enum_string( VIPS_TYPE_IMAGE_TYPE, n ) ); }
const char *im_dhint2char( VipsDemandStyle style ) 
	{ return( vips_enum_string( VIPS_TYPE_DEMAND_STYLE, style ) ); }

/* Old names for enums, for compat.
 */
static const char *im_Type[] = {
	"IM_TYPE_MULTIBAND", 		/* 0 */
	"IM_TYPE_B_W", 			/* 1 */
	"LUMINACE", 			/* 2 */
	"XRAY", 			/* 3 */
	"IR", 				/* 4 */
	"YUV", 				/* 5 */
	"RED_ONLY", 			/* 6 */
	"GREEN_ONLY", 			/* 7 */
	"BLUE_ONLY", 			/* 8 */
	"POWER_SPECTRUM", 		/* 9 */
	"IM_TYPE_HISTOGRAM", 		/* 10 */
	"LUT", 				/* 11 */
	"IM_TYPE_XYZ",			/* 12 */
	"IM_TYPE_LAB", 			/* 13 */
	"CMC", 				/* 14 */
	"IM_TYPE_CMYK", 		/* 15 */
	"IM_TYPE_LABQ", 		/* 15 */
	"IM_TYPE_RGB", 			/* 17 */
	"IM_TYPE_UCS", 			/* 18 */
	"IM_TYPE_LCH", 			/* 19 */
	"IM_TYPE_LABS",			/* 20 */
	"<unknown>", 			/* 21 */
	"IM_TYPE_sRGB", 		/* 22 */
	"IM_TYPE_YXY", 			/* 23 */
	"IM_TYPE_FOURIER",		/* 24 */
	"IM_TYPE_RGB16",		/* 25 */
	"IM_TYPE_GREY16",		/* 26 */
	NULL
};

static const char *im_BandFmt[] = {
	"IM_BANDFMT_UCHAR", 
	"IM_BANDFMT_CHAR", 
	"IM_BANDFMT_USHORT", 
	"IM_BANDFMT_SHORT", 
	"IM_BANDFMT_UINT", 
	"IM_BANDFMT_INT", 
	"IM_BANDFMT_FLOAT", 
	"IM_BANDFMT_COMPLEX", 
	"IM_BANDFMT_DOUBLE", 
	"IM_BANDFMT_DPCOMPLEX",
	NULL
};

static const char *im_Coding[] = {
	"IM_CODING_NONE", 
	"COLQUANT8", 
	"IM_CODING_LABQ", 
	"IM_CODING_LABQ_COMPRESSED",
	"RGB_COMPRESSED",
	"LUM_COMPRESSED",
	"IM_CODING_RAD",
	NULL
};

static const char *im_dtype[] = {
	"IM_NONE", 
	"IM_SETBUF", 
	"IM_SETBUF_FOREIGN", 
	"IM_OPENIN", 
	"IM_MMAPIN", 
	"IM_MMAPINRW", 
	"IM_OPENOUT", 
	"IM_PARTIAL",
	NULL
};

static const char *im_dhint[] = {
	"IM_SMALLTILE", 
	"IM_FATSTRIP", 
	"IM_THINSTRIP", 
	"IM_ANY",
	NULL
};

/* enum string to int, try the GEnum first, then use a compat *char[] for old
 * names.
 */
static int
lookup_enum( GType type, const char *names[], const char *name )
{
	GEnumClass *class;
	GEnumValue *value;
	int i;

	class = g_type_class_ref( type );
	if( (value = g_enum_get_value_by_nick( class, name )) )
		return( value->value );
	if( (value = g_enum_get_value_by_name( class, name )) )
		return( value->value );

	for( i = 0; names[i]; i++ )
		if( strcasecmp( names[i], name ) == 0 )
			return( i );

	return( -1 );
}

VipsInterpretation im_char2Type( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_INTERPRETATION, im_Type, str ) ); }
VipsBandFormat im_char2BandFmt( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_BAND_FORMAT, im_BandFmt, str ) ); }
VipsCoding im_char2Coding( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_CODING, im_Coding, str ) ); }
VipsImageType im_char2dtype( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_IMAGE_TYPE, im_dtype, str ) ); }
VipsDemandStyle im_char2dhint( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_DEMAND_STYLE, im_dhint, str ) ); }

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

	for( n = 0; in[n]; n++ )
		;
	new = VIPS_ARRAY( VIPS_OBJECT( out ), n + 1, IMAGE * );
	for( i = 0; i < n; i++ )
		new[i] = in[i];
	new[n] = NULL;

	return( new );
}

int
im_wrapmany( IMAGE **in, IMAGE *out, im_wrapmany_fn fn, void *a, void *b )
{
	Bundle *bun;
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
	bun = VIPS_NEW( VIPS_OBJECT( out ), Bundle );
	if( !(in = dupims( out, in )) )
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
        vips_demand_hint_array( out, VIPS_DEMAND_STYLE_THINSTRIP, in );

	/* Generate!
	 */
	if( vips_image_generate( out,
		vips_start_many, (VipsGenerateFn) process_region, 
		vips_stop_many, in, bun ) )
		return( -1 );

	return( 0 );
}

static void
wrapone_gen( void **ins, void *out, int width, Bundle *bun, void *dummy )
{
	((im_wrapone_fn) (bun->fn)) (ins[0], out, width, bun->a, bun->b );
}

int
im_wrapone( IMAGE *in, IMAGE *out, im_wrapone_fn fn, void *a, void *b )
{
	Bundle *bun;
	IMAGE *invec[2];

	/* Heh, yuk. We cast back above.
	 */
	bun = VIPS_NEW( VIPS_OBJECT( out ), Bundle );
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

int
im_wraptwo( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	im_wraptwo_fn fn, void *a, void *b )
{
	Bundle *bun;
	IMAGE *invec[3];

	bun = VIPS_NEW( VIPS_OBJECT( out ), Bundle );
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
	VipsImage *x;

	if( vips_call( "add", in1, in2, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_subtract( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "subtract", in1, in2, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_multiply( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "multiply", in1, in2, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_divide( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "divide", in1, in2, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_avg( IMAGE *in, double *out )
{
	return( vips_avg( in, out, NULL ) ); 
}

int
im_deviate( IMAGE *in, double *out )
{
	return( vips_deviate( in, out, NULL ) ); 
}

int im_generate( VipsImage *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b )
{
	return( vips_image_generate( im, 
		start, (VipsGenerateFn) generate, stop, a, b ) );
}

int
im_minpos( IMAGE *in, int *xpos, int *ypos, double *out )
{
	return( vips_min( in, out, "x", xpos, "y", ypos, NULL ) );
}

int
im_min( IMAGE *in, double *out )
{
	return( im_minpos( in, NULL, NULL, out ) );
}

int
im_maxpos( IMAGE *in, int *xpos, int *ypos, double *out )
{
	return( vips_max( in, out, "x", xpos, "y", ypos, NULL ) );
}

int
im_max( IMAGE *in, double *out )
{
	return( im_maxpos( in, NULL, NULL, out ) );
}

#define MAX_IMAGES 100
int
im_demand_hint (IMAGE * im, VipsDemandStyle hint, ...)
{
  va_list ap;
  int i;
  IMAGE *ar[MAX_IMAGES];

  va_start (ap, hint);
  for (i = 0; i < MAX_IMAGES && (ar[i] = va_arg (ap, IMAGE *)); i++)
    ;
  va_end (ap);
  if (i == MAX_IMAGES)
    {
      im_error ("im_demand_hint", "%s", _("too many images"));
      return (-1);
    }

  return (im_demand_hint_array (im, hint, ar));
}

int 
im_copy_set( IMAGE *in, IMAGE *out, 
	VipsType type, float xres, float yres, int xoffset, int yoffset )
{
	VipsImage *x;

	if( vips_copy( in, &x, 
		"interpretation", type, 
		"xres", xres, 
		"yres", yres, 
		"xoffset", xoffset, 
		"yoffset", yoffset, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_copy_morph( IMAGE *in, IMAGE *out, 
	int bands, VipsBandFmt bandfmt, VipsCoding coding )
{
	VipsImage *x;

	if( vips_copy( in, &x, 
		"bands", bands, 
		"format", bandfmt, 
		"coding", coding, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_copy( IMAGE *in, IMAGE *out )
{
	return( vips_image_write( in, out ) ); 
}

int
im_copy_swap( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_copy( in, &x, 
		"swap", TRUE, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_copy_set_meta( IMAGE *in, IMAGE *out, const char *field, GValue *value )
{
	if( im_copy( in, out ) )
		return( -1 );
	im_meta_set( out, field, value );

	return( 0 );
}

int
im_copy_native( IMAGE *in, IMAGE *out, gboolean is_msb_first )
{
	if( is_msb_first != im_amiMSBfirst() )
		return( im_copy_swap( in, out ) );
	else
		return( im_copy( in, out ) );
}

int
im_embed( IMAGE *in, IMAGE *out, int type, int x, int y, int width, int height )
{
	VipsImage *t;

	if( vips_embed( in, &t, x, y, width, height,
		"extend", type, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_fliphor( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_flip( in, &t, VIPS_DIRECTION_HORIZONTAL, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_rot90( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_rot( in, &t, VIPS_ANGLE_90, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_rot180( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_rot( in, &t, VIPS_ANGLE_180, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_rot270( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_rot( in, &t, VIPS_ANGLE_270, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_flipver( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_flip( in, &t, VIPS_DIRECTION_VERTICAL, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_insert( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y )
{
	VipsImage *t;

	if( vips_insert( main, sub, &t, x, y, 
		"expand", TRUE, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_insert_noexpand( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y )
{
	VipsImage *t;

	if( vips_insert( main, sub, &t, x, y, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_lrjoin( IMAGE *left, IMAGE *right, IMAGE *out )
{
	VipsImage *t;

	if( vips_join( left, right, &t, VIPS_DIRECTION_HORIZONTAL,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_tbjoin( IMAGE *left, IMAGE *right, IMAGE *out )
{
	VipsImage *t;

	if( vips_join( left, right, &t, VIPS_DIRECTION_VERTICAL,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_extract_area( IMAGE *in, IMAGE *out, 
	int left, int top, int width, int height )
{
	VipsImage *t;

	if( vips_extract_area( in, &t, left, top, width, height,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_extract_bands( IMAGE *in, IMAGE *out, int band, int nbands )
{
	VipsImage *t;

	if( vips_extract_band( in, &t, band,
		"n", nbands,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_extract_band( IMAGE *in, IMAGE *out, int band )
{
	return( im_extract_bands( in, out, band, 1 ) ); 
}

int
im_extract_areabands( IMAGE *in, IMAGE *out, 
	int left, int top, int width, int height, int band, int nbands )
{
	VipsImage *t1, *t2;

	if( vips_extract_area( in, &t1, left, top, width, height,
		NULL ) )
		return( -1 );

	if( vips_extract_band( t1, &t2, band,
		"n", nbands,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );

	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int 
im_replicate( IMAGE *in, IMAGE *out, int across, int down )
{
	VipsImage *t;

	if( vips_replicate( in, &t, across, down,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_clip2fmt( IMAGE *in, IMAGE *out, VipsBandFmt fmt ) 
{
	VipsImage *t;

	if( vips_cast( in, &t, fmt,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

size_t 
im_ref_string_get_length( const GValue *value )
{
	size_t length;

	(void) vips_value_get_ref_string( value, &length );

	return( length );
}

int 
im_bandjoin( VipsImage *in1, VipsImage *in2, VipsImage *out )
{
	VipsImage *t;

	if( vips_bandjoin2( in1, in2, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_gbandjoin( VipsImage **in, VipsImage *out, int n )
{
	VipsImage *t;

	if( vips_bandjoin( in, &t, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_invert( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_invert( in, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_sign( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_sign( in, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_abs( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_abs( in, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_bandmean( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_bandmean( in, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_lintra( double a, IMAGE *in, double b, IMAGE *out )
{
	VipsImage *t;

	if( vips_linear1( in, &t, a, b,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_lintra_vec( int n, double *a, IMAGE *in, double *b, IMAGE *out )
{
	VipsImage *t;

	if( vips_linear( in, &t, a, b, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_black( IMAGE *out, int x, int y, int bands )
{
	VipsImage *t;

	if( vips_black( &t, x, y,
		"bands", bands,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
vips__math( VipsImage *in, VipsImage *out, VipsOperationMath math )
{
	VipsImage *t;

	if( vips_math( in, &t, math,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_sintra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_SIN ) );
}

int 
im_costra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_COS ) );
}

int 
im_tantra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_TAN ) );
}

int 
im_asintra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_ASIN ) );
}

int 
im_acostra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_ACOS ) );
}

int 
im_atantra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_ATAN ) );
}

int 
im_logtra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_LOG ) );
}

int 
im_log10tra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_LOG10 ) );
}

int 
im_exptra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_EXP ) );
}

int 
im_exp10tra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_EXP10 ) );
}

DOUBLEMASK *
im_stats( VipsImage *in )
{
	VipsImage *t;
	DOUBLEMASK *msk;

	if( vips_stats( in, &t,
		NULL ) )
		return( NULL );
	if( !(msk = im_vips2mask( t, "im_stats" )) ) {
		g_object_unref( t );
		return( NULL );
	}
	g_object_unref( t );

	return( msk );
}

int 
im_recomb( IMAGE *in, IMAGE *out, DOUBLEMASK *recomb )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_mask2vips( recomb, t1 ) )
		return( -1 );
	if( vips_recomb( in, &t2, t1, 
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

static int
vips__round( VipsImage *in, VipsImage *out, VipsOperationRound round )
{
	VipsImage *t;

	if( vips_round( in, &t, round,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_rint( IMAGE *in, IMAGE *out )
{
	return( vips__round( in, out, VIPS_OPERATION_ROUND_RINT ) );
}

int 
im_floor( IMAGE *in, IMAGE *out )
{
	return( vips__round( in, out, VIPS_OPERATION_ROUND_FLOOR ) );
}

int 
im_ceil( IMAGE *in, IMAGE *out )
{
	return( vips__round( in, out, VIPS_OPERATION_ROUND_CEIL ) );
}

static int 
vips__relational( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	VipsOperationRelational relational )
{
	VipsImage *t;

	if( vips_relational( in1, in2, &t, relational,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_equal( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_EQUAL ) );
}

int 
im_notequal( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_NOTEQUAL ) );
}

int 
im_less( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_LESS ) );
}

int 
im_lesseq( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_LESSEQ ) );
}

int 
im_more( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_MORE ) );
}

int 
im_moreeq( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_MOREEQ ) );
}

static int 
vips__relational_vec( IMAGE *in, IMAGE *out, 
	VipsOperationRelational relational, double *c, int n )
{
	VipsImage *t;

	if( vips_relational_const( in, &t, relational, c, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_equal_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_EQUAL, c, n ) );
}

int 
im_notequal_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_NOTEQUAL, c, n ) );
}

int 
im_less_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_LESS, c, n ) );
}

int 
im_lesseq_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_LESSEQ, c, n ) );
}

int 
im_more_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_MORE, c, n ) );
}

int 
im_moreeq_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_MOREEQ, c, n ) );
}

int 
im_equalconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_equal_vec( in, out, 1, &c ) );
}

int
im_notequalconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_notequal_vec( in, out, 1, &c ) );
}

int
im_lessconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_less_vec( in, out, 1, &c ) );
}

int
im_lesseqconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_lesseq_vec( in, out, 1, &c ) );
}

int
im_moreconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_more_vec( in, out, 1, &c ) );
}

int
im_moreeqconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_moreeq_vec( in, out, 1, &c ) );
}

int 
im_remainder( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *t;

	if( vips_remainder( in1, in2, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_remainder_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	VipsImage *t;

	if( vips_remainder_const( in, &t, c, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_remainderconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_remainder_vec( in, out, 1, &c ) );
}

static int 
vips__boolean( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	VipsOperationBoolean boolean )
{
	VipsImage *t;

	if( vips_boolean( in1, in2, &t, boolean,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_andimage( VipsImage *in1, VipsImage *in2, VipsImage *out )
{
	return( vips__boolean( in1, in2, out, VIPS_OPERATION_BOOLEAN_AND ) );
}

int 
im_orimage( VipsImage *in1, VipsImage *in2, VipsImage *out )
{
	return( vips__boolean( in1, in2, out, VIPS_OPERATION_BOOLEAN_OR ) );
}

int 
im_eorimage( VipsImage *in1, VipsImage *in2, VipsImage *out )
{
	return( vips__boolean( in1, in2, out, VIPS_OPERATION_BOOLEAN_EOR ) );
}

static int 
vips__boolean_vec( IMAGE *in, IMAGE *out, 
	VipsOperationBoolean boolean, double *c, int n )
{
	VipsImage *t;

	if( vips_boolean_const( in, &t, boolean, c, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_andimage_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_AND, c, n ) );
}

int 
im_orimage_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_OR, c, n ) );
}

int 
im_eorimage_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_EOR, c, n ) );
}

int 
im_shiftleft_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_LSHIFT, c, n ) );
}

int 
im_shiftright_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_RSHIFT, c, n ) );
}

int 
im_andimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_andimage_vec( in, out, 1, &c ) ); 
}

int 
im_orimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_orimage_vec( in, out, 1, &c ) );
}

int 
im_eorimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_eorimage_vec( in, out, 1, &c ) );
}

int 
im_shiftleft( IMAGE *in, IMAGE *out, int n )
{
	double c = n;

	return( im_shiftleft_vec( in, out, 1, &c ) );
}

int 
im_shiftright( IMAGE *in, IMAGE *out, int n )
{
	double c = n;

	return( im_shiftright_vec( in, out, 1, &c ) );
}

static int 
vips__math2_vec( IMAGE *in, IMAGE *out, 
	VipsOperationMath2 math2, double *c, int n )
{
	VipsImage *t;

	if( vips_math2_const( in, &t, math2, c, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_powtra_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__math2_vec( in, out, VIPS_OPERATION_MATH2_POW, c, n ) );
}

int 
im_powtra( IMAGE *in, IMAGE *out, double c )
{
	return( im_powtra_vec( in, out, 1, &c ) );
}

int 
im_expntra_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( vips__math2_vec( in, out, VIPS_OPERATION_MATH2_WOP, c, n ) );
}

int 
im_expntra( IMAGE *in, IMAGE *out, double c )
{
	return( im_expntra_vec( in, out, 1, &c ) );
}

int 
im_ifthenelse( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out )
{
	VipsImage *t;

	if( vips_ifthenelse( c, a, b, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_blend( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out )
{
	VipsImage *t;

	if( vips_ifthenelse( c, a, b, &t, 
		"blend", TRUE,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
vips__complex( VipsImage *in, VipsImage *out, VipsOperationComplex cmplx )
{
	VipsImage *t;

	if( vips_complex( in, &t, cmplx,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_c2amph( IMAGE *in, IMAGE *out )
{
	return( vips__complex( in, out, VIPS_OPERATION_COMPLEX_POLAR ) );
}

int 
im_c2rect( IMAGE *in, IMAGE *out )
{
	return( vips__complex( in, out, VIPS_OPERATION_COMPLEX_RECT ) );
}

static int
vips__complexget( VipsImage *in, VipsImage *out, VipsOperationComplexget get )
{
	VipsImage *t;

	if( vips_complexget( in, &t, get,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_c2real( IMAGE *in, IMAGE *out )
{
	return( vips__complexget( in, out, VIPS_OPERATION_COMPLEXGET_REAL ) );
}

int 
im_c2imag( IMAGE *in, IMAGE *out )
{
	return( vips__complexget( in, out, VIPS_OPERATION_COMPLEXGET_IMAG ) );
}

int 
im_ri2c( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "complexform", in1, in2, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_cache( VipsImage *in, VipsImage *out, 
	int width, int height, int max )
{
	return( vips_sink_screen( in, out, NULL, 
		width, height, max, 0, NULL, NULL ) );
}

int
im_argb2rgba( VipsImage *in, VipsImage *out )
{
	/* No longer exists, just a null op.
	 */
	return( im_copy( in, out ) );
}

int
im_shrink( VipsImage *in, VipsImage *out, double xshrink, double yshrink )
{
	VipsImage *x;

	if( vips_shrink( in, &x, xshrink, yshrink, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_rightshift_size( IMAGE *in, IMAGE *out, 
	int xshift, int yshift, int band_fmt )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 2 );

	if( vips_shrink( in, &t[0], 1 << xshift, 1 << yshift, NULL ) ||
		vips_cast( t[0], &t[1], band_fmt, NULL ) ||
		vips_image_write( t[1], out ) ) 
		return( -1 );

	return( 0 );
}

int 
im_Lab2XYZ_temp( IMAGE *in, IMAGE *out, double X0, double Y0, double Z0 )
{
	double ary[3];
	VipsArea *temp;
	VipsImage *x;

	ary[0] = X0;
	ary[1] = Y0;
	ary[2] = Z0;
	temp = (VipsArea *) vips_array_double_new( ary, 3 ); 
	if( vips_Lab2XYZ( in, &x, "temp", temp, NULL ) ) {
		vips_area_unref( temp );
		return( -1 );
	}
	vips_area_unref( temp );

	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2XYZ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Lab2XYZ( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_XYZ2Lab_temp( IMAGE *in, IMAGE *out, double X0, double Y0, double Z0 )
{
	double ary[3];
	VipsArea *temp;
	VipsImage *x;

	ary[0] = X0;
	ary[1] = Y0;
	ary[2] = Z0;
	temp = (VipsArea *) vips_array_double_new( ary, 3 ); 
	if( vips_XYZ2Lab( in, &x, "temp", temp, NULL ) ) {
		vips_area_unref( temp );
		return( -1 );
	}
	vips_area_unref( temp );

	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_XYZ2Lab( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_XYZ2Lab( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2LCh( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Lab2LCh( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LCh2Lab( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LCh2Lab( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LCh2UCS( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LCh2UCS( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_UCS2LCh( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_UCS2LCh( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_XYZ2Yxy( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_XYZ2Yxy( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Yxy2XYZ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Yxy2XYZ( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_float2rad( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_float2rad( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_rad2float( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_rad2float( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2LabQ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Lab2LabQ( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabQ2Lab( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabQ2Lab( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2LabS( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Lab2LabS( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabS2Lab( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabS2Lab( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabQ2LabS( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabQ2LabS( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabS2LabQ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabS2LabQ( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2disp( IMAGE *in, IMAGE *out, struct im_col_display *disp )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_Lab2disp:1", "p" ) ||
		im_Lab2XYZ( in, t[0] ) ||
		im_XYZ2disp( t[0], out, disp ) )
		return( -1 );

	return( 0 );
}

int 
im_dECMC_fromdisp( IMAGE *im1, IMAGE *im2, 
	IMAGE *out, struct im_col_display *d )
{	
	IMAGE *t[4];

	if( im_open_local_array( out, t, 4, "im_dECMC_fromdisp:1", "p" ) ||
		im_disp2XYZ( im1, t[0], d ) ||
		im_XYZ2Lab( t[0], t[1] ) ||
		im_disp2XYZ( im2, t[2], d ) ||
		im_XYZ2Lab( t[2], t[3] ) ||
		im_dECMC_fromLab( t[1], t[3], out ) )
		return( -1 );

	return( 0 );
}

int 
im_dE_fromdisp( IMAGE *im1, IMAGE *im2, IMAGE *out, struct im_col_display *d )
{
	IMAGE *t[2];

	if( im_open_local_array( out, t, 2, "im_dE_fromdisp:1", "p" ) ||
		im_disp2XYZ( im1, t[0], d ) ||
		im_disp2XYZ( im2, t[1], d ) ||
		im_dE_fromXYZ( t[0], t[1], out ) )
		return( -1 );

	return( 0 );
}

int 
im_disp2Lab( IMAGE *in, IMAGE *out, struct im_col_display *d )
{
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_disp2Lab:1", "p" ) ||
		im_disp2XYZ( in, t[0], d ) ||
		im_XYZ2Lab( t[0], out ) )
		return( -1 );
	
	return( 0 );
}

int 
im_sRGB2XYZ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_sRGB2XYZ( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_XYZ2sRGB( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_XYZ2sRGB( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabQ2sRGB( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabQ2sRGB( in, &x, NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_icc_transform( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename,
	const char *output_profile_filename,
	VipsIntent intent )
{
	VipsImage *x;

	if( vips_icc_transform( in, &x, output_profile_filename,
		"input_profile", input_profile_filename,
		"intent", intent,
		NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_icc_import( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename, VipsIntent intent )
{
	VipsImage *x;

	if( vips_icc_import( in, &x, 
		"input_profile", input_profile_filename,
		"intent", intent,
		NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_icc_import_embedded( VipsImage *in, VipsImage *out, VipsIntent intent )
{
	VipsImage *x;

	if( vips_icc_import( in, &x, 
		"embedded", TRUE,
		"intent", intent,
		NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_icc_export_depth( VipsImage *in, VipsImage *out, int depth,
	const char *output_profile_filename, VipsIntent intent )
{
	VipsImage *x;

	if( vips_icc_export( in, &x, output_profile_filename,
		"depth", depth,
		"intent", intent,
		NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}
