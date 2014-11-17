/* cast an image to a numerical format
 *
 * Author: Nicos Dessipris
 * Written on: 07/03/1991
 * Modified on: 
 * 04/05/1992 JC
 *	- works for char, uchar too
 *	- floating point code removed from integer clip operations
 *	- uses nint() instead of own rounding code
 *	- calculated the number of >255 clips for float/double input
 *	  incorrectly
 *	- rejects complex input correctly now
 * 27/4/93 JC
 *	- adapted to work with partial images
 *	- nint() removed, now just +0.5
 *	- im_warning code removed
 * 30/6/93 JC
 *	- adapted for partial v2
 * 31/8/93 JC
 *	- now detects and prints over/underflows
 * 27/10/93 JC
 *	- unsigned integer clips now faster!
 *	- falls back to im_copy() correctly
 * 5/5/94 JC
 *	- switched to rint()
 * 18/8/94 JC
 *	- now uses evalend callback
 * 9/5/95 JC
 *	- now does complex too
 * 11/7/95 JC
 *	- now uses IM_RINT() macro
 * 10/3/01 JC
 *	- slightly faster and simpler
 *	- generalised to im_clip2fmt(), all other clippers now just call
 *	  this
 * 21/4/04 JC
 *	- now does floor(), not rint() ... you'll need to round yourself
 *	  before calling this if you want round-to-nearest
 * 7/11/07
 * 	- use new evalstart/evalend system
 * 26/8/08
 * 	- oops, complex->complex conversion was broken
 * 27/1/10
 * 	- modernised
 * 	- gtk-doc
 * 27/10/11
 * 	- redone as a class
 * 10/4/12
 * 	- cast to uint now removes <0 values
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

typedef struct _VipsCast {
	VipsConversion parent_instance;

	VipsImage *in;
	VipsBandFormat format;

	int underflow;		/* Number of underflows */
	int overflow;		/* Number of overflows */

} VipsCast;

typedef VipsConversionClass VipsCastClass;

G_DEFINE_TYPE( VipsCast, vips_cast, VIPS_TYPE_CONVERSION );

static void
vips_cast_preeval( VipsImage *image, VipsProgress *progress, VipsCast *cast )
{
	cast->overflow = 0;
	cast->underflow = 0;
}

static void
vips_cast_posteval( VipsImage *image, VipsProgress *progress, VipsCast *cast )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( cast );

	if( cast->overflow || cast->underflow ) 
		vips_warn( class->nickname, 
			_( "%d underflows and %d overflows detected" ),
			cast->underflow, cast->overflow );
}

/* Our sequence value: the region this sequence is using, and two local stats.
 */
typedef struct {
	VipsRegion *ir;		/* Input region */

	int underflow;		/* Number of underflows */
	int overflow;		/* Number of overflows */
} VipsCastSequence;

/* Destroy a sequence value.
 */
static int
vips_cast_stop( void *vseq, void *a, void *b )
{
	VipsCastSequence *seq = (VipsCastSequence *) vseq;
	VipsCast *cast = (VipsCast *) b;

	/* Add to global stats.
	 */
	cast->underflow += seq->underflow;
	cast->overflow += seq->overflow;

	VIPS_FREEF( g_object_unref, seq->ir );

	g_free( seq );

	return( 0 );
}

/* Make a sequence value.
 */
static void *
vips_cast_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsCastSequence *seq;
	 
	seq = g_new( VipsCastSequence, 1 );
	seq->ir = vips_region_new( in );
	seq->overflow = 0;
	seq->underflow = 0;

	if( !seq->ir ) {
		vips_cast_stop( seq, a, b );
		return( NULL );
	}

	return( seq );
}

/* Cast int types to an int type.
 */
#define VIPS_CLIP_INT_INT( ITYPE, OTYPE, VIPS_CLIP ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		int t = p[x]; \
		\
		VIPS_CLIP( t, seq ); \
		\
		q[x] = t; \
	} \
}

/* Cast float types to an int type.
 */
#define VIPS_CLIP_FLOAT_INT( ITYPE, OTYPE, VIPS_CLIP ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		ITYPE v = floor( p[x] ); \
		\
		VIPS_CLIP( v, seq ); \
		\
		q[x] = v; \
	} \
}

/* Cast complex types to an int type. Just take the real part.
 */
#define VIPS_CLIP_COMPLEX_INT( ITYPE, OTYPE, VIPS_CLIP ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		ITYPE v = floor( p[0] ); \
		p += 2; \
		\
		VIPS_CLIP( v, seq ); \
		\
		q[x] = v; \
	} \
}

/* Cast non-complex types to a float type.
 */
#define VIPS_CLIP_REAL_FLOAT( ITYPE, OTYPE ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p[x]; \
}

/* Cast complex types to a float type ... just take real.
 */
#define VIPS_CLIP_COMPLEX_FLOAT( ITYPE, OTYPE ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[x] = p[0]; \
		p += 2; \
	} \
}

/* Cast any non-complex to a complex type ... set imaginary to zero.
 */
#define VIPS_CLIP_REAL_COMPLEX( ITYPE, OTYPE ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[0] = p[x]; \
		q[1] = 0.0; \
		q += 2; \
	} \
}

/* Cast any complex to a complex type.
 */
#define VIPS_CLIP_COMPLEX_COMPLEX( ITYPE, OTYPE ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[0] = p[0]; \
		q[1] = p[1]; \
		p += 2; \
		q += 2; \
	} \
}

#define BAND_SWITCH_INNER( ITYPE, INT, FLOAT, COMPLEX ) { \
	switch( conversion->out->BandFmt ) { \
	case VIPS_FORMAT_UCHAR: \
		INT( ITYPE, unsigned char, VIPS_CLIP_UCHAR ); \
		break; \
	\
	case VIPS_FORMAT_CHAR: \
		INT( ITYPE, signed char, VIPS_CLIP_CHAR ); \
		break; \
	\
	case VIPS_FORMAT_USHORT: \
		INT( ITYPE, unsigned short, VIPS_CLIP_USHORT ); \
		break; \
	\
	case VIPS_FORMAT_SHORT: \
		INT( ITYPE, signed short, VIPS_CLIP_SHORT ); \
		break; \
	\
	case VIPS_FORMAT_UINT: \
		INT( ITYPE, unsigned int, VIPS_CLIP_UINT ); \
		break; \
	\
	case VIPS_FORMAT_INT: \
		INT( ITYPE, signed int, VIPS_CLIP_NONE ); \
		break; \
	\
	case VIPS_FORMAT_FLOAT: \
		FLOAT( ITYPE, float ); \
		break; \
	\
	case VIPS_FORMAT_DOUBLE: \
		FLOAT( ITYPE, double ); \
		break; \
	\
	case VIPS_FORMAT_COMPLEX: \
		COMPLEX( ITYPE, float ); \
		break; \
	\
	case VIPS_FORMAT_DPCOMPLEX: \
		COMPLEX( ITYPE, double ); \
		break; \
	\
	default: \
		g_assert( 0 ); \
	} \
}

static int
vips_cast_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsCastSequence *seq = (VipsCastSequence *) vseq;
	VipsRegion *ir = seq->ir;
	VipsCast *cast = (VipsCast *) b;
	VipsConversion *conversion = (VipsConversion *) b;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );
	int sz = VIPS_REGION_N_ELEMENTS( or );
	int x, y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	VIPS_GATE_START( "vips_cast_gen: work" );

	for( y = to; y < bo; y++ ) {
		VipsPel *in = VIPS_REGION_ADDR( ir, le, y ); 
		VipsPel *out = VIPS_REGION_ADDR( or, le, y ); 

		switch( cast->in->BandFmt ) { 
		case VIPS_FORMAT_UCHAR: 
			BAND_SWITCH_INNER( unsigned char,
				VIPS_CLIP_INT_INT, 
				VIPS_CLIP_REAL_FLOAT, 
				VIPS_CLIP_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_CHAR: 
			BAND_SWITCH_INNER( signed char,
				VIPS_CLIP_INT_INT, 
				VIPS_CLIP_REAL_FLOAT, 
				VIPS_CLIP_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_USHORT: 
			BAND_SWITCH_INNER( unsigned short,
				VIPS_CLIP_INT_INT, 
				VIPS_CLIP_REAL_FLOAT, 
				VIPS_CLIP_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_SHORT: 
			BAND_SWITCH_INNER( signed short,
				VIPS_CLIP_INT_INT, 
				VIPS_CLIP_REAL_FLOAT, 
				VIPS_CLIP_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_UINT: 
			BAND_SWITCH_INNER( unsigned int,
				VIPS_CLIP_INT_INT, 
				VIPS_CLIP_REAL_FLOAT, 
				VIPS_CLIP_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_INT: 
			BAND_SWITCH_INNER( signed int,
				VIPS_CLIP_INT_INT, 
				VIPS_CLIP_REAL_FLOAT, 
				VIPS_CLIP_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_FLOAT: 
			BAND_SWITCH_INNER( float,
				VIPS_CLIP_FLOAT_INT, 
				VIPS_CLIP_REAL_FLOAT, 
				VIPS_CLIP_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_DOUBLE: 
			BAND_SWITCH_INNER( double,
				VIPS_CLIP_FLOAT_INT, 
				VIPS_CLIP_REAL_FLOAT, 
				VIPS_CLIP_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_COMPLEX: 
			BAND_SWITCH_INNER( float,
				VIPS_CLIP_COMPLEX_INT, 
				VIPS_CLIP_COMPLEX_FLOAT, 
				VIPS_CLIP_COMPLEX_COMPLEX );
			break; 

		case VIPS_FORMAT_DPCOMPLEX: 
			BAND_SWITCH_INNER( double,
				VIPS_CLIP_COMPLEX_INT, 
				VIPS_CLIP_COMPLEX_FLOAT, 
				VIPS_CLIP_COMPLEX_COMPLEX );
			break; 

		default: 
			g_assert( 0 ); 
		} 
	}

	VIPS_GATE_STOP( "vips_cast_gen: work" );

	return( 0 );
}

static int
vips_cast_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsCast *cast = (VipsCast *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 2 );

	VipsImage *in; 

	if( VIPS_OBJECT_CLASS( vips_cast_parent_class )->build( object ) )
		return( -1 );

	in = cast->in; 

	/* Trivial case: fall back to copy().
	 */
	if( in->BandFmt == cast->format ) 
		return( vips_image_write( in, conversion->out ) );

	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0]; 

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );

	conversion->out->BandFmt = cast->format;

	g_signal_connect( in, "preeval", 
		G_CALLBACK( vips_cast_preeval ), cast );
	g_signal_connect( in, "posteval", 
		G_CALLBACK( vips_cast_posteval ), cast );

	if( vips_image_generate( conversion->out,
		vips_cast_start, vips_cast_gen, vips_cast_stop, 
		in, cast ) )
		return( -1 );

	return( 0 );
}

static void
vips_cast_class_init( VipsCastClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_cast_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "cast";
	vobject_class->description = _( "cast an image" );
	vobject_class->build = vips_cast_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCast, in ) );

	VIPS_ARG_ENUM( class, "format", 6, 
		_( "Format" ), 
		_( "Format to cast to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCast, format ),
		VIPS_TYPE_BAND_FORMAT, VIPS_FORMAT_UCHAR ); 
}

static void
vips_cast_init( VipsCast *cast )
{
}

static int
vips_castv( VipsImage *in, VipsImage **out, VipsBandFormat format, va_list ap )
{
	return( vips_call_split( "cast", ap, in, out, format ) );
}

/**
 * vips_cast:
 * @in: input image
 * @out: output image
 * @format: format to convert to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to @format. You can convert between any pair of formats.
 * Floats are truncated (not rounded). Out of range values are clipped.
 *
 * Casting from complex to real returns the real part. 
 *
 * See also: vips_scale(), vips_complexform(), vips_real(), vips_imag(),
 * vips_cast_uchar().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast( VipsImage *in, VipsImage **out, VipsBandFormat format, ... )
{
	va_list ap;
	int result;

	va_start( ap, format );
	result = vips_castv( in, out, format, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_uchar:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_UCHAR. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_uchar( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_UCHAR, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_char:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_CHAR. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_char( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_CHAR, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_ushort:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_USHORT. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_ushort( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_USHORT, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_short:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_SHORT. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_short( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_SHORT, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_uint:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_UINT. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_uint( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_UINT, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_int:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_INT. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_int( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_INT, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_float:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_FLOAT. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_float( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_FLOAT, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_double:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_DOUBLE. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_double( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_DOUBLE, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_complex:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_COMPLEX. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_complex( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_COMPLEX, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cast_dpcomplex:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert @in to #VIPS_FORMAT_DPCOMPLEX. See vips_cast(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cast_dpcomplex( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_castv( in, out, VIPS_FORMAT_DPCOMPLEX, ap );
	va_end( ap );

	return( result );
}

