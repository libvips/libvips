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
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

/**
 * VipsCast:
 * @in: input image
 * @out: output image
 * @format: format to convert to
 *
 * Convert @in to @format. You can convert between any pair of formats.
 * Floats are truncated (not rounded). Out of range values are clipped.
 *
 * See also: im_scale(), im_ri2c().
 */

typedef struct _VipsCast {
	VipsConversion parent_instance;

	VipsImage *input;
	VipsBandFormat format;

} VipsCast;

typedef VipsConversionClass VipsCastClass;

G_DEFINE_TYPE( VipsCast, vips_cast, VIPS_TYPE_CONVERSION );

/* Clip int types to an int type.
 */
#define VIPS_CLIP_INT_INT( ITYPE, OTYPE, VIPS_CLIP ) { \
	ITYPE *p = (ITYPE *) in; \
	OTYPE *q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		int t = p[x]; \
		\
		VIPS_CLIP( t, seq ); \
		\
		q[x] = t; \
	} \
}

/* Clip float types to an int type.
 */
#define VIPS_CLIP_FLOAT_INT( ITYPE, OTYPE, VIPS_CLIP ) { \
	ITYPE *p = (ITYPE *) in; \
	OTYPE *q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		ITYPE v = floor( p[x] ); \
		\
		VIPS_CLIP( v, seq ); \
		\
		q[x] = v; \
	} \
}

/* Clip complex types to an int type. Just take the real part.
 */
#define VIPS_CLIP_COMPLEX_INT( ITYPE, OTYPE, VIPS_CLIP ) { \
	ITYPE *p = (ITYPE *) in; \
	OTYPE *q = (OTYPE *) out; \
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

/* Clip non-complex types to a float type.
 */
#define VIPS_CLIP_REAL_FLOAT( ITYPE, OTYPE ) { \
	ITYPE *p = (ITYPE *) in; \
	OTYPE *q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p[x]; \
}

/* Clip complex types to a float type ... just take real.
 */
#define VIPS_CLIP_COMPLEX_FLOAT( ITYPE, OTYPE ) { \
	ITYPE *p = (ITYPE *) in; \
	OTYPE *q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[x] = p[0]; \
		p += 2; \
	} \
}

/* Clip any non-complex to a complex type ... set imaginary to zero.
 */
#define VIPS_CLIP_REAL_COMPLEX( ITYPE, OTYPE ) { \
	ITYPE *p = (ITYPE *) in; \
	OTYPE *q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[0] = p[x]; \
		q[1] = 0.0; \
		q += 2; \
	} \
}

/* Clip any complex to a complex type.
 */
#define VIPS_CLIP_COMPLEX_COMPLEX( ITYPE, OTYPE ) { \
	ITYPE *p = (ITYPE *) in; \
	OTYPE *q = (OTYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[0] = p[0]; \
		q[1] = p[1]; \
		p += 2; \
		q += 2; \
	} \
}

#define BAND_SWITCH_INNER( ITYPE, INT, FLOAT, COMPLEX ) { \
	switch( clip->out->BandFmt ) { \
	case VIPS_FORMAT_UCHAR: \
		INT( ITYPE, unsigned char, VIPS_CLIP_UCHAR ); \
		break; \
	case VIPS_FORMAT_CHAR: \
		INT( ITYPE, signed char, VIPS_CLIP_CHAR ); \
		break; \
	case VIPS_FORMAT_USHORT: \
		INT( ITYPE, unsigned short, VIPS_CLIP_USHORT ); \
		break; \
	case VIPS_FORMAT_SHORT: \
		INT( ITYPE, signed short, VIPS_CLIP_SHORT ); \
		break; \
	case VIPS_FORMAT_UINT: \
		INT( ITYPE, unsigned int, VIPS_CLIP_NONE ); \
		break; \
	case VIPS_FORMAT_INT: \
		INT( ITYPE, signed int, VIPS_CLIP_NONE ); \
		break; \
	case VIPS_FORMAT_FLOAT: \
		FLOAT( ITYPE, float ); \
		break; \
	case VIPS_FORMAT_DOUBLE: \
		FLOAT( ITYPE, double ); \
		break; \
	case VIPS_FORMAT_COMPLEX: \
		COMPLEX( ITYPE, float ); \
		break; \
	case VIPS_FORMAT_DPCOMPLEX: \
		COMPLEX( ITYPE, double ); \
		break; \
	default: \
		g_assert( 0 ); \
	} \
}

static int
vips_cast_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	Clip *clip = (Clip *) b;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);
	int sz = VIPS_REGION_N_ELEMENTS( or );
	int x, y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	for( y = to; y < bo; y++ ) {
		PEL *in = (PEL *) VIPS_REGION_ADDR( ir, le, y ); 
		PEL *out = (PEL *) VIPS_REGION_ADDR( or, le, y ); 

		switch( clip->in->BandFmt ) { 
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

	return( 0 );
}

static int
vips_cast_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsCast *cast = (VipsCast *) object;

	VipsGenerateFn generate_fn;

	if( VIPS_OBJECT_CLASS( vips_cast_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( cast->input ) || 
		vips_image_pio_output( conversion->output ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->output, cast->input ) )
		return( -1 );
	vips_demand_hint( conversion->output, 
		VIPS_DEMAND_STYLE_THINSTRIP, cast->input, NULL );

	conversion->output->BandFmt = cast->format

	if( vips_image_generate( conversion->output,
		vips_start_one, generate_fn, vips_stop_one, 
		cast->input, cast ) )
		return( -1 );

	return( 0 );
}

static void
vips_cast_class_init( VipsCastClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_cast_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "cast";
	vobject_class->description = _( "cast an image" );
	vobject_class->build = vips_cast_build;

	VIPS_ARG_IMAGE( class, "input", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCast, input ) );

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

int
vips_cast( VipsImage *in, VipsImage **out, VipsBandFormat format, ... )
{
	va_list ap;
	int result;

	va_start( ap, direction );
	result = vips_call_split( "cast", ap, in, out, format );
	va_end( ap );

	return( result );
}
