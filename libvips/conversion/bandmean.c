/* im_bandmean.c
 *
 * Author: Simon Goodall
 * Written on: 17/7/07
 * 17/7/07 JC
 * 	- hacked about a bit
 * 18/8/09
 * 	- gtkdoc
 * 	- get rid of the complex case, just double the width
 * 19/11/11
 * 	- redo as a class
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

#include "conversion.h"

typedef struct _VipsBandmean {
	VipsConversion parent_instance;

	VipsImage *in;

} VipsBandmean;

typedef VipsConversionClass VipsBandmeanClass;

G_DEFINE_TYPE( VipsBandmean, vips_bandmean, VIPS_TYPE_CONVERSION );

/* Unsigned int types. Round, keep sum in a larger variable.
 */
#define UILOOP( TYPE, STYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( i = 0; i < sz; i++ ) { \
		STYPE sum; \
		\
		sum = 0; \
		for( j = 0; j < bands; j++ ) \
			sum += p[j]; \
		q[i] = (sum + bands / 2) / bands; \
		p += bands; \
	} \
}

/* Signed int types. Round, keep sum in a larger variable.
 */
#define SILOOP( TYPE, STYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( i = 0; i < sz; i++ ) { \
		STYPE sum; \
		\
		sum = 0; \
		for( j = 0; j < bands; j++ ) \
			sum += p[j]; \
		q[i] = sum > 0 ? \
			(sum + bands / 2) / bands : \
			(sum - bands / 2) / bands; \
		p += bands; \
	} \
}

/* Float loop. No rounding, sum in same container.
 */
#define FLOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( i = 0; i < sz; i++ ) { \
		TYPE sum; \
		\
		sum = 0; \
		for( j = 0; j < bands; j++ ) \
			sum += p[j]; \
		q[i] = sum / bands; \
		p += bands; \
	} \
}

static int
vips_bandmean_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsBandmean *bandmean = (VipsBandmean *) b;
	VipsImage *im = bandmean->in;
	VipsRect *r = &or->valid;
	const int bands = im->Bands;
	const int sz = r->width * 
		(vips_bandfmt_iscomplex( im->BandFmt ) ? 2 : 1);

	int y, i, j;

	if( vips_region_prepare( ir, r ) ) 
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		PEL *in = (PEL *) VIPS_REGION_ADDR( ir, r->left, r->top + y );
		PEL *out = (PEL *) VIPS_REGION_ADDR( or, r->left, r->top + y );

		switch( vips_image_get_format( im ) ) {
		case VIPS_FORMAT_CHAR: 	
			SILOOP( signed char, int ); break; 
		case VIPS_FORMAT_UCHAR:	
			UILOOP( unsigned char, unsigned int ); break; 
		case VIPS_FORMAT_SHORT: 	
			SILOOP( signed short, int ); break; 
		case VIPS_FORMAT_USHORT:	
			UILOOP( unsigned short, unsigned int ); break; 
		case VIPS_FORMAT_INT: 	
			SILOOP( signed int, int ); break; 
		case VIPS_FORMAT_UINT: 	
			UILOOP( unsigned int, unsigned int ); break; 
		case VIPS_FORMAT_FLOAT: 	
			FLOOP( float ); break; 
		case VIPS_FORMAT_DOUBLE:	
			FLOOP( double ); break; 
		case VIPS_FORMAT_COMPLEX:
			FLOOP( float ); break;
		case VIPS_FORMAT_DPCOMPLEX:
			FLOOP( double ); break;

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

static int
vips_bandmean_build( VipsObject *object )
{
	VipsConversion *conversion = (VipsConversion *) object;
	VipsBandmean *bandmean = (VipsBandmean *) object;

	if( VIPS_OBJECT_CLASS( vips_bandmean_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( bandmean->in ) || 
		vips_check_uncoded( "VipsBandmean", bandmean->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, bandmean->in ) )
		return( -1 );
        vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, bandmean->in, NULL );
	conversion->out->Bands = 1;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_bandmean_gen, vips_stop_one, 
		bandmean->in, bandmean ) )
		return( -1 );

	return( 0 );
}

static void
vips_bandmean_class_init( VipsBandmeanClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "bandmean";
	object_class->description = _( "band-wise average" );
	object_class->build = vips_bandmean_build;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandmean, in ) );
}

static void
vips_bandmean_init( VipsBandmean *bandmean )
{
}

/**
 * vips_bandmean:
 * @in: input #IMAGE
 * @out: output #IMAGE
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation writes a one-band image where each pixel is the average of 
 * the bands for that pixel in the input image. The output band format is 
 * the same as the input band format. Integer types use round-to-nearest
 * averaging.
 *
 * See also: vips_add(), vips_avg(), vips_recomb()
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandmean( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "bandmean", ap, in, out );
	va_end( ap );

	return( result );
}
