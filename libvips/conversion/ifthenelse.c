/* ifthenelse.c --- use a condition image to join two images together
 *
 * Modified:
 * 9/2/95 JC
 *	- partialed and ANSIfied
 * 11/9/95 JC
 *	- return( 0 ) missing! oops
 * 15/4/05
 *	- now just evals left/right if all zero/all one
 * 7/10/06
 * 	- set THINSTRIP
 * 23/9/09
 * 	- gtkdoc comment
 * 23/9/09
 * 	- use im_check*()
 * 	- allow many-band conditional and single-band a/b
 * 	- allow a/b to differ in format and bands
 * 25/6/10
 * 	- let the conditional image be any format by adding a (!=0) if
 * 	  necessary
 * 17/5/11
 * 	- added sizealike
 * 14/11/11
 * 	- redone as a class
 * 19/4/12
 * 	- fix blend
 * 	- small blend speedup
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

typedef struct _VipsIfthenelse {
	VipsConversion parent_instance;

	/* Params.
	 */
	VipsImage *cond;
	VipsImage *in1;
	VipsImage *in2;

	gboolean blend;

} VipsIfthenelse;

typedef VipsConversionClass VipsIfthenelseClass;

G_DEFINE_TYPE( VipsIfthenelse, vips_ifthenelse, VIPS_TYPE_CONVERSION );

#define IBLEND1( TYPE ) { \
	TYPE *a = (TYPE *) ap; \
	TYPE *b = (TYPE *) bp; \
	TYPE *q = (TYPE *) qp; \
 	\
	for( i = 0, x = 0; x < n; i++, x += bands ) { \
		const int v = c[i]; \
 		\
		for( z = x; z < x + bands; z++ )  \
			q[z] = (v * a[z] + (255 - v) * b[z] + 128) / 255; \
	} \
}

#define IBLENDN( TYPE ) { \
	TYPE *a = (TYPE *) ap; \
	TYPE *b = (TYPE *) bp; \
	TYPE *q = (TYPE *) qp; \
 	\
	for( x = 0; x < n; x += bands ) { \
		for( z = x; z < x + bands; z++ ) { \
			const int v = c[z]; \
 			\
			q[z] = (v * a[z] + (255 - v) * b[z] + 128) / 255; \
		} \
	} \
}

#define FBLEND1( TYPE ) { \
	TYPE *a = (TYPE *) ap; \
	TYPE *b = (TYPE *) bp; \
	TYPE *q = (TYPE *) qp; \
 	\
	for( i = 0, x = 0; x < n; i++, x += bands ) { \
		const double v = c[i] / 255.0; \
 		\
		for( z = x; z < x + bands; z++ )  \
			q[z] = v * a[z] + (1.0 - v) * b[z]; \
	} \
}

#define FBLENDN( TYPE ) { \
	TYPE *a = (TYPE *) ap; \
	TYPE *b = (TYPE *) bp; \
	TYPE *q = (TYPE *) qp; \
 	\
	for( x = 0; x < n; x += bands ) { \
		for( z = x; z < x + bands; z++ ) { \
			const double v = c[z] / 255.0; \
 			\
			q[z] = v * a[z] + (1.0 - v) * b[z]; \
		} \
	} \
}

#define CBLEND1( TYPE ) { \
	TYPE *a = (TYPE *) ap; \
	TYPE *b = (TYPE *) bp; \
	TYPE *q = (TYPE *) qp; \
 	\
	for( i = 0, x = 0; x < n; i++, x += bands ) { \
		const double v = c[i] / 255.0; \
 		\
		for( z = x; z < x + 2 * bands; z++ )  \
			q[z] = v * a[z] + (1.0 - v) * b[z]; \
	} \
}

#define CBLENDN( TYPE ) { \
	TYPE *a = (TYPE *) ap; \
	TYPE *b = (TYPE *) bp; \
	TYPE *q = (TYPE *) qp; \
 	\
	for( x = 0; x < n; x += bands ) { \
		for( z = x; z < x + bands; z++ ) { \
			const double v = c[z] / 255.0; \
 			\
			q[2 * z] = v * a[2 * z] + (1.0 - v) * b[2 * z]; \
			q[2 * z + 1] = v * a[2 * z + 1] + \
				(1.0 - v) * b[2 * z + 1]; \
		} \
	} \
}

/* Blend with a 1-band conditional image.
 */
static void
vips_blend1_buffer( VipsPel *qp, 
	VipsPel *c, VipsPel *ap, VipsPel *bp, int width, 
	VipsImage *im )
{
	int i, x, z;
	const int bands = im->Bands;
	const int n = width * bands;

	switch( im->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	IBLEND1( unsigned char ); break;
	case VIPS_FORMAT_CHAR: 		IBLEND1( signed char ); break;
	case VIPS_FORMAT_USHORT: 	IBLEND1( unsigned short ); break;
	case VIPS_FORMAT_SHORT: 	IBLEND1( signed short ); break;
	case VIPS_FORMAT_UINT: 		IBLEND1( unsigned int ); break;
	case VIPS_FORMAT_INT: 		IBLEND1( signed int );  break;
	case VIPS_FORMAT_FLOAT: 	FBLEND1( float ); break;
	case VIPS_FORMAT_DOUBLE: 	FBLEND1( double ); break;
	case VIPS_FORMAT_COMPLEX: 	CBLEND1( float ); break;
	case VIPS_FORMAT_DPCOMPLEX: 	CBLEND1( double ); break;

	default:
		g_assert( 0 );
	}
}

/* Blend with a many band conditional image.
 */
static void
vips_blendn_buffer( VipsPel *qp, 
	VipsPel *c, VipsPel *ap, VipsPel *bp, int width, 
	VipsImage *im )
{
	int x, z;
	const int bands = im->Bands;
	const int n = width * bands;

	switch( im->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	IBLENDN( unsigned char ); break;
	case VIPS_FORMAT_CHAR: 		IBLENDN( signed char ); break;
	case VIPS_FORMAT_USHORT: 	IBLENDN( unsigned short ); break;
	case VIPS_FORMAT_SHORT: 	IBLENDN( signed short ); break;
	case VIPS_FORMAT_UINT: 		IBLENDN( unsigned int ); break;
	case VIPS_FORMAT_INT: 		IBLENDN( signed int );  break;
	case VIPS_FORMAT_FLOAT: 	FBLENDN( float ); break;
	case VIPS_FORMAT_DOUBLE: 	FBLENDN( double ); break;
	case VIPS_FORMAT_COMPLEX: 	CBLENDN( float ); break;
	case VIPS_FORMAT_DPCOMPLEX: 	CBLENDN( double ); break;

	default:
		g_assert( 0 );
	}
}

static int
vips_blend_gen( VipsRegion *or, void *seq, void *client1, void *client2,
	gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );

	VipsImage *c = ir[2]->im;
	VipsImage *a = ir[0]->im;

	int x, y;
	int all0, all255;

	if( vips_region_prepare( ir[2], r ) )
		return( -1 );

	/* Is the conditional all zero or all 255? We can avoid asking
	 * for one of the inputs to be calculated.
	 */
	all0 = *VIPS_REGION_ADDR( ir[2], le, to ) == 0;
	all255 = *VIPS_REGION_ADDR( ir[2], le, to ) == 255;
	for( y = to; y < bo; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir[2], le, y );
		int width = r->width * c->Bands;

		for( x = 0; x < width; x++ ) {
			all0 &= p[x] == 0;
			all255 &= p[x] == 255;
		}

		if( !all0 && !all255 )
			break;
	}

	if( all255 ) {
		/* All 255. Point or at the then image.
		 */
		if( vips_region_prepare( ir[0], r ) ||
			vips_region_region( or, ir[0], r, r->left, r->top ) )
			return( -1 );
	}
	else if( all0 ) {
		/* All zero. Point or at the else image.
		 */
		if( vips_region_prepare( ir[1], r ) ||
			vips_region_region( or, ir[1], r, r->left, r->top ) )
			return( -1 );
	}
	else {
		/* Mix of set and clear ... ask for both then and else parts 
		 * and interleave.
		 */
		if( vips_region_prepare( ir[0], r ) || 
			vips_region_prepare( ir[1], r ) ) 
			return( -1 );

		for( y = to; y < bo; y++ ) {
			VipsPel *ap = VIPS_REGION_ADDR( ir[0], le, y );
			VipsPel *bp = VIPS_REGION_ADDR( ir[1], le, y );
			VipsPel *cp = VIPS_REGION_ADDR( ir[2], le, y );
			VipsPel *q = VIPS_REGION_ADDR( or, le, y );

			if( c->Bands == 1 ) 
				vips_blend1_buffer( q, cp, ap, bp, 
					r->width, a );
			else
				vips_blendn_buffer( q, cp, ap, bp, 
					r->width, a );
		}
	}

	return( 0 );
}

static int
vips_ifthenelse_gen( VipsRegion *or, void *seq, void *client1, void *client2,
	gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );

	VipsImage *c = ir[2]->im;
	VipsImage *a = ir[0]->im;

	int size, width;
	int i, x, y, z;

	int all0, alln0;

	if( c->Bands == 1 ) {
		/* Copying PEL-sized units with a one-band conditional.
		 */
		size = VIPS_IMAGE_SIZEOF_PEL( a );
		width = r->width;
	}
	else {
		/* Copying ELEMENT sized-units with an n-band conditional.
		 */
		size = VIPS_IMAGE_SIZEOF_ELEMENT( a );
		width = r->width * a->Bands;
	}

	if( vips_region_prepare( ir[2], r ) )
		return( -1 );

	/* Is the conditional all zero or all non-zero? We can avoid asking
	 * for one of the inputs to be calculated.
	 */
	all0 = *VIPS_REGION_ADDR( ir[2], le, to ) == 0;
	alln0 = *VIPS_REGION_ADDR( ir[2], le, to ) != 0;
	for( y = to; y < bo; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir[2], le, y );

		for( x = 0; x < width; x++ ) {
			all0 &= p[x] == 0;
			alln0 &= p[x] != 0;
		}

		if( !all0 && !alln0 )
			break;
	}

	if( alln0 ) {
		/* All non-zero. Point or at the then image.
		 */
		if( vips_region_prepare( ir[0], r ) ||
			vips_region_region( or, ir[0], r, r->left, r->top ) )
			return( -1 );
	}
	else if( all0 ) {
		/* All zero. Point or at the else image.
		 */
		if( vips_region_prepare( ir[1], r ) ||
			vips_region_region( or, ir[1], r, r->left, r->top ) )
			return( -1 );
	}
	else {
		/* Mix of set and clear ... ask for both then and else parts 
		 * and interleave.
		 */
		if( vips_region_prepare( ir[0], r ) || 
			vips_region_prepare( ir[1], r ) ) 
			return( -1 );

		for( y = to; y < bo; y++ ) {
			VipsPel *ap = VIPS_REGION_ADDR( ir[0], le, y );
			VipsPel *bp = VIPS_REGION_ADDR( ir[1], le, y );
			VipsPel *cp = VIPS_REGION_ADDR( ir[2], le, y );
			VipsPel *q = VIPS_REGION_ADDR( or, le, y );

			for( x = 0, i = 0; i < width; i++, x += size ) 
				if( cp[i] )
					for( z = x; z < x + size; z++ )
						q[z] = ap[z];
				else
					for( z = x; z < x + size; z++ )
						q[z] = bp[z];
		}
	}

	return( 0 );
}

static int
vips_ifthenelse_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsIfthenelse *ifthenelse = (VipsIfthenelse *) object;
	VipsGenerateFn generate_fn = ifthenelse->blend ? 
		vips_blend_gen : vips_ifthenelse_gen;

	VipsImage **band = (VipsImage **) vips_object_local_array( object, 3 );
	VipsImage **size = (VipsImage **) vips_object_local_array( object, 3 );
	VipsImage **format = 
		(VipsImage **) vips_object_local_array( object, 3 );


	VipsImage *all[3];

	if( VIPS_OBJECT_CLASS( vips_ifthenelse_parent_class )->build( object ) )
		return( -1 );

	/* We have to have the condition image last since we want the output
	 * image to inherit its properties from the then/else parts.
	 */
	all[0] = ifthenelse->in1;
	all[1] = ifthenelse->in2;
	all[2] = ifthenelse->cond;

	/* No need to check input images, sizealike and friends will do this
	 * for us.
	 */

	/* Cast our input images up to a common bands and size.
	 */
	if( vips__bandalike_vec( "VipsIfthenelse", all, band, 3, 0 ) ||
		vips__sizealike_vec( band, size, 3 ) )
		return( -1 );

	/* Condition is cast to uchar, then/else to a common type.
	 */
	if( vips_cast( size[2], &format[2], VIPS_FORMAT_UCHAR, NULL ) )
		return( -1 );
	if( vips__formatalike_vec( size, format, 2 ) ) 
		return( -1 ); 

	if( vips_image_copy_fields_array( conversion->out, format ) )
		return( -1 );
        vips_demand_hint_array( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, format );

	if( vips_image_generate( conversion->out,
		vips_start_many, generate_fn, vips_stop_many, 
		format, ifthenelse ) )
		return( -1 );

	return( 0 );
}

static void
vips_ifthenelse_class_init( VipsIfthenelseClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_ifthenelse_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "ifthenelse";
	vobject_class->description = _( "ifthenelse an image" );
	vobject_class->build = vips_ifthenelse_build;

	VIPS_ARG_IMAGE( class, "cond", -2, 
		_( "Condition" ), 
		_( "Condition input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsIfthenelse, cond ) );

	VIPS_ARG_IMAGE( class, "in1", -1, 
		_( "Then image" ), 
		_( "Source for TRUE pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsIfthenelse, in1 ) );

	VIPS_ARG_IMAGE( class, "in2", 0, 
		_( "Else image" ), 
		_( "Source for FALSE pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsIfthenelse, in2 ) );

	VIPS_ARG_BOOL( class, "blend", 4, 
		_( "blend" ), 
		_( "Blend smoothly between then and else parts" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsIfthenelse, blend ),
		FALSE );
}

static void
vips_ifthenelse_init( VipsIfthenelse *ifthenelse )
{
}

/**
 * vips_ifthenelse:
 * @cond: condition #VipsImage
 * @in1: then #VipsImage
 * @in2: else #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @blend: blend smoothly between @in1 and @in2
 *
 * This operation scans the condition image @cond 
 * and uses it to select pixels from either the then image @in1 or the else
 * image @in2. Non-zero means @in1, 0 means @in2.
 *
 * Any image can have either 1 band or n bands, where n is the same for all
 * the non-1-band images. Single band images are then effectively copied to 
 * make n-band images.
 *
 * Images @in1 and @in2 are cast up to the smallest common format. @cond is
 * cast to uchar.
 *
 * If the images differ in size, the smaller images are enlarged to match the
 * largest by adding zero pixels along the bottom and right.
 *
 * If @blend is %TRUE, then values in @out are smoothly blended between @in1
 * and @in2 using the formula:
 *
 *   @out = (@cond / 255) * @in1 + (1 - @cond / 255) * @in2
 *
 * See also: vips_equal().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_ifthenelse( VipsImage *cond, VipsImage *in1, VipsImage *in2, 
	VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "ifthenelse", ap, cond, in1, in2, out );
	va_end( ap );

	return( result );
}
