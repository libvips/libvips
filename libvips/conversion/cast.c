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
 * 11/2/15
 * 	- add @shift option
 * 1/3/16
 * 	- better behaviour for shift of non-int types (thanks apacheark)
 * 14/11/18
 * 	- revise for better uint/int clipping [erdmann]
 * 	- remove old overflow/underflow detect
 * 8/12/20
 * 	- fix range clip in int32 -> unsigned casts [ewelot]
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
#include <glib/gi18n-lib.h>

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
	gboolean shift;

} VipsCast;

typedef VipsConversionClass VipsCastClass;

G_DEFINE_TYPE( VipsCast, vips_cast, VIPS_TYPE_CONVERSION );

/* Cast down from an int.
 */
#define CAST_UCHAR( X ) VIPS_CLIP( 0, (X), UCHAR_MAX )
#define CAST_CHAR( X ) VIPS_CLIP( SCHAR_MIN, (X), SCHAR_MAX )
#define CAST_USHORT( X ) VIPS_CLIP( 0, (X), USHRT_MAX )
#define CAST_SHORT( X ) VIPS_CLIP( SHRT_MIN, (X), SHRT_MAX )

/* These cast down from gint64 to uint32 or int32. 
 */
#define CAST_UINT( X ) VIPS_CLIP( 0, (X), UINT_MAX )
#define CAST_INT( X ) VIPS_CLIP( INT_MIN, (X), INT_MAX )

/* Rightshift an integer type, ie. sizeof(ITYPE) >= sizeof(OTYPE).
 *
 * If we're casting between two formats of the same size (eg. ushort to
 * short), sizes can be equal.
 */
#define SHIFT_RIGHT( ITYPE, OTYPE ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	int n = ((int) sizeof( ITYPE ) << 3) - ((int) sizeof( OTYPE ) << 3); \
	\
	g_assert( sizeof( ITYPE ) >= sizeof( OTYPE ) ); \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p[x] >> n; \
}

/* Leftshift an integer type, ie. sizeof(ITYPE) <= sizeof(OTYPE). We need to
 * copy the bottom bit up into the fresh new bits.
 */
#define SHIFT_LEFT( ITYPE, OTYPE ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	int n = ((int) sizeof( OTYPE ) << 3) - ((int) sizeof( ITYPE ) << 3); \
	\
	g_assert( sizeof( ITYPE ) <= sizeof( OTYPE ) ); \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = (p[x] << n) | (((p[x] & 1) << n) - (p[x] & 1)); \
}

#define SHIFT_LEFT_SIGNED( ITYPE, OTYPE ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	int n = ((int) sizeof( OTYPE ) << 3) - ((int) sizeof( ITYPE ) << 3); \
	\
	g_assert( sizeof( ITYPE ) <= sizeof( OTYPE ) ); \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = VIPS_LSHIFT_INT( p[x], n ) | \
			(((p[x] & 1) << n) - (p[x] & 1)); \
}

/* Cast int types to an int type. We need to pass in the type of the
 * intermediate value, either int or int64, or we'll have problems with uint
 * sources turning -ve.
 */
#define CAST_INT_INT( ITYPE, OTYPE, TEMP, CAST ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		TEMP t = (TEMP) p[x]; \
		\
		q[x] = CAST( t ); \
	} \
}

/* Int to int handling. 
 */
#define INT_INT( ITYPE, OTYPE, TEMP, CAST ) { \
	if( cast->shift && \
		sizeof( ITYPE ) > sizeof( OTYPE ) ) { \
		SHIFT_RIGHT( ITYPE, OTYPE ); \
	} \
	else if( cast->shift ) { \
		SHIFT_LEFT( ITYPE, OTYPE ); \
	} \
	else { \
		CAST_INT_INT( ITYPE, OTYPE, TEMP, CAST ); \
	} \
} 

/* Int to int handling for signed int types. 
 */
#define INT_INT_SIGNED( ITYPE, OTYPE, TEMP, CAST ) { \
	if( cast->shift && \
		sizeof( ITYPE ) > sizeof( OTYPE ) ) { \
		SHIFT_RIGHT( ITYPE, OTYPE ); \
	} \
	else if( cast->shift ) { \
		SHIFT_LEFT_SIGNED( ITYPE, OTYPE ); \
	} \
	else { \
		CAST_INT_INT( ITYPE, OTYPE, TEMP, CAST ); \
	} \
} 

/* Cast float types to an int type.
 *
 * We need to do the range clip as double or we'll get errors for int max,
 * since that can't be represented as a 32-bit float.
 */
#define CAST_FLOAT_INT( ITYPE, OTYPE, TEMP, CAST ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = CAST( (double) p[x] ); \
}

/* Cast complex types to an int type. Just take the real part.
 *
 * We need to do the range clip as double or we'll get errors for int max,
 * since that can't be represented as a 32-bit float.
 */
#define CAST_COMPLEX_INT( ITYPE, OTYPE, TEMP, CAST ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[x] = CAST( (double) p[0] ); \
		p += 2; \
	} \
}

/* Cast non-complex types to a float type.
 */
#define CAST_REAL_FLOAT( ITYPE, OTYPE ) { \
	ITYPE * restrict p = (ITYPE *) in; \
	OTYPE * restrict q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p[x]; \
}

/* Cast complex types to a float type ... just take real.
 */
#define CAST_COMPLEX_FLOAT( ITYPE, OTYPE ) { \
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
#define CAST_REAL_COMPLEX( ITYPE, OTYPE ) { \
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
#define CAST_COMPLEX_COMPLEX( ITYPE, OTYPE ) { \
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
		INT( ITYPE, unsigned char, int, CAST_UCHAR ); \
		break; \
	\
	case VIPS_FORMAT_CHAR: \
		INT( ITYPE, signed char, int, CAST_CHAR ); \
		break; \
	\
	case VIPS_FORMAT_USHORT: \
		INT( ITYPE, unsigned short, int, CAST_USHORT ); \
		break; \
	\
	case VIPS_FORMAT_SHORT: \
		INT( ITYPE, signed short, int, CAST_SHORT ); \
		break; \
	\
	case VIPS_FORMAT_UINT: \
		INT( ITYPE, unsigned int, gint64, CAST_UINT ); \
		break; \
	\
	case VIPS_FORMAT_INT: \
		INT( ITYPE, signed int, gint64, CAST_INT ); \
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
		g_assert_not_reached(); \
	} \
}

static int
vips_cast_gen( VipsRegion *or, void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsCast *cast = (VipsCast *) b;
	VipsConversion *conversion = (VipsConversion *) b;
	VipsRect *r = &or->valid;
	int sz = VIPS_REGION_N_ELEMENTS( or );

	int x, y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	VIPS_GATE_START( "vips_cast_gen: work" );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *in = VIPS_REGION_ADDR( ir, r->left, r->top + y ); 
		VipsPel *out = VIPS_REGION_ADDR( or, r->left, r->top + y ); 

		switch( ir->im->BandFmt ) { 
		case VIPS_FORMAT_UCHAR: 
			BAND_SWITCH_INNER( unsigned char,
				INT_INT, 
				CAST_REAL_FLOAT, 
				CAST_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_CHAR: 
			BAND_SWITCH_INNER( signed char,
				INT_INT_SIGNED, 
				CAST_REAL_FLOAT, 
				CAST_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_USHORT: 
			BAND_SWITCH_INNER( unsigned short,
				INT_INT, 
				CAST_REAL_FLOAT, 
				CAST_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_SHORT: 
			BAND_SWITCH_INNER( signed short,
				INT_INT_SIGNED, 
				CAST_REAL_FLOAT, 
				CAST_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_UINT: 
			BAND_SWITCH_INNER( unsigned int,
				INT_INT, 
				CAST_REAL_FLOAT, 
				CAST_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_INT: 
			BAND_SWITCH_INNER( signed int,
				INT_INT_SIGNED, 
				CAST_REAL_FLOAT, 
				CAST_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_FLOAT: 
			BAND_SWITCH_INNER( float,
				CAST_FLOAT_INT, 
				CAST_REAL_FLOAT, 
				CAST_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_DOUBLE: 
			BAND_SWITCH_INNER( double,
				CAST_FLOAT_INT, 
				CAST_REAL_FLOAT, 
				CAST_REAL_COMPLEX );
			break; 

		case VIPS_FORMAT_COMPLEX: 
			BAND_SWITCH_INNER( float,
				CAST_COMPLEX_INT, 
				CAST_COMPLEX_FLOAT, 
				CAST_COMPLEX_COMPLEX );
			break; 

		case VIPS_FORMAT_DPCOMPLEX: 
			BAND_SWITCH_INNER( double,
				CAST_COMPLEX_INT, 
				CAST_COMPLEX_FLOAT, 
				CAST_COMPLEX_COMPLEX );
			break; 

		default: 
			g_assert_not_reached(); 
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

	/* If @shift is on but we're not in an int format and we're going to
	 * an int format, we need to cast to int first. For example, what 
	 * about a float image tagged as rgb16 being cast to uint8? We need 
	 * to cast to ushort before we do the final cast to uint8.
	 */
	if( cast->shift && 
		!vips_band_format_isint( in->BandFmt ) &&
		vips_band_format_isint( cast->format ) ) {
		if( vips_cast( in, &t[1], 
			vips_image_guess_format( in ), NULL ) )
			return( -1 );
		in = t[1];
	}

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );

	conversion->out->BandFmt = cast->format;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_cast_gen, vips_stop_one, 
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

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

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

	VIPS_ARG_BOOL( class, "shift", 7, 
		_( "Shift" ), 
		_( "Shift integer values up and down" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCast, shift ),
		FALSE );
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
 * vips_cast: (method)
 * @in: input image
 * @out: (out): output image
 * @format: format to convert to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @shift: %gboolean, integer values are shifted
 *
 * Convert @in to @format. You can convert between any pair of formats.
 * Floats are truncated (not rounded). Out of range values are clipped.
 *
 * Casting from complex to real returns the real part. 
 *
 * If @shift is %TRUE, integer values are shifted up and down. For example,
 * casting from unsigned 8 bit to unsigned 16 bit would
 * shift every value left by 8 bits. The bottom bit is copied into the new
 * bits, so 255 would become 65535.  
 *
 * See also: vips_scale(), vips_complexform(), vips_real(), vips_imag(),
 * vips_cast_uchar(), vips_msb().
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
 * vips_cast_uchar: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_char: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_ushort: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_short: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_uint: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_int: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_float: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_double: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_complex: (method)
 * @in: input image
 * @out: (out): output image
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
 * vips_cast_dpcomplex: (method)
 * @in: input image
 * @out: (out): output image
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

