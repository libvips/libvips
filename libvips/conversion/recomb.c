/* recomb.c ... pass an image though a matrix
 *
 * 21/6/95 JC
 *	- mildly modernised
 * 14/3/96 JC
 *	- better error checks, partial
 * 4/11/09
 * 	- gtkdoc
 * 9/11/11
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

typedef struct _VipsRecomb {
	VipsConversion parent_instance;

	VipsImage *in;
	VipsImage *m;

	/* m converted to a one-band double.
	 */
	double *coeff;

} VipsRecomb;

typedef VipsConversionClass VipsRecombClass;

G_DEFINE_TYPE( VipsRecomb, vips_recomb, VIPS_TYPE_CONVERSION );

/* Inner loop.
 */
#define LOOP( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < or->valid.width; x++ ) { \
		double *m; \
		\
		m = recomb->coeff; \
		\
		for( v = 0; v < mheight; v++ ) { \
			double t; \
			\
			t = 0.0; \
			\
			for( u = 0; u < mwidth; u++ ) \
				t += m[u] * p[u]; \
			\
			q[v] = (OUT) t; \
			m += mwidth; \
		} \
		\
		p += mwidth; \
		q += mheight; \
	} \
}

static int
vips_recomb_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRecomb *recomb = (VipsRecomb *) b;
	VipsImage *im = recomb->in;
	int mwidth = recomb->m->Xsize;
	int mheight = recomb->m->Ysize;

	int y, x, u, v;

	if( vips_region_prepare( ir, &or->valid ) ) 
		return( -1 );

	for( y = 0; y < or->valid.height; y++ ) {
		VipsPel *in = VIPS_REGION_ADDR( ir, 
			or->valid.left, or->valid.top + y );
		VipsPel *out = VIPS_REGION_ADDR( or, 
			or->valid.left, or->valid.top + y );

		switch( vips_image_get_format( im ) ) {
		case VIPS_FORMAT_UCHAR: LOOP( unsigned char, float ); break;
		case VIPS_FORMAT_CHAR: 	LOOP( signed char, float ); break; 
		case VIPS_FORMAT_USHORT:LOOP( unsigned short, float ); break; 
		case VIPS_FORMAT_SHORT: LOOP( signed short, float ); break; 
		case VIPS_FORMAT_UINT: 	LOOP( unsigned int, float ); break; 
		case VIPS_FORMAT_INT: 	LOOP( signed int, float );  break; 
		case VIPS_FORMAT_FLOAT: LOOP( float, float ); break; 
		case VIPS_FORMAT_DOUBLE:LOOP( double, double ); break; 

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

static int
vips_recomb_build( VipsObject *object )
{
	VipsConversion *conversion = (VipsConversion *) object;
	VipsRecomb *recomb = (VipsRecomb *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	if( VIPS_OBJECT_CLASS( vips_recomb_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( recomb->in ) || 
		vips_check_uncoded( "VipsRecomb", recomb->in ) ||
		vips_check_noncomplex( "VipsRecomb", recomb->in ) )
		return( -1 );
	if( vips_image_pio_input( recomb->m ) || 
		vips_check_uncoded( "VipsRecomb", recomb->m ) ||
		vips_check_noncomplex( "VipsRecomb", recomb->m ) ||
		vips_check_mono( "VipsRecomb", recomb->m ) )
		return( -1 );
	if( recomb->in->Bands != recomb->m->Xsize ) {
		vips_error( "VipsRecomb", 
			"%s", _( "bands in must equal matrix width" ) );
		return( -1 );
	}

	if( vips_cast( recomb->m, &t[0], VIPS_FORMAT_DOUBLE, NULL ) ||
		vips_image_wio_input( t[0] ) )
		return( -1 );
	recomb->coeff = (double *) VIPS_IMAGE_ADDR( t[0], 0, 0 );

	if( vips_image_copy_fields( conversion->out, recomb->in ) )
		return( -1 );
        vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, recomb->in, NULL );

	conversion->out->Bands = recomb->m->Ysize;
	if( vips_bandfmt_isint( recomb->in->BandFmt ) ) 
		conversion->out->BandFmt = VIPS_FORMAT_FLOAT;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_recomb_gen, vips_stop_one, 
		recomb->in, recomb ) )
		return( -1 );

	return( 0 );
}

static void
vips_recomb_class_init( VipsRecombClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "recomb";
	object_class->description = _( "linear recombination with matrix" );
	object_class->build = vips_recomb_build;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRecomb, in ) );

	VIPS_ARG_IMAGE( class, "m", 102, 
		_( "M" ), 
		_( "matrix of coefficients" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsRecomb, m ) );
}

static void
vips_recomb_init( VipsRecomb *recomb )
{
}

/** 
 * vips_recomb:
 * @in: input image
 * @out: output image
 * @m: recombination matrix
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation recombines an image's bands. Each pixel in @in is treated as 
 * an n-element vector, where n is the number of bands in @in, and multipled by
 * the n x m matrix @m to produce the m-band image @out.
 *
 * @out is always float, unless @in is double, in which case @out is double
 * too. No complex images allowed.
 *
 * It's useful for various sorts of colour space conversions.
 *
 * See also: vips_bandmean().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_recomb( VipsImage *in, VipsImage **out, VipsImage *m, ... )
{
	va_list ap;
	int result;

	va_start( ap, m );
	result = vips_call_split( "recomb", ap, in, out, m );
	va_end( ap );

	return( result );
}
