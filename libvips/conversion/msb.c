/* vips_msb()
 *
 * Copyright: 2006, The Nottingham Trent University
 *
 * Author: Tom Vajzovic
 *
 * Written on: 2006-03-13
 * 27/9/06
 * 	- removed extra im_free() in im_copy() fallback
 * 4/10/06
 * 	- removed warning on uchar fallback: it happens a lot with nip2 and
 * 	  isn't very serious
 * 1/2/10
 * 	- revised, cleanups
 * 	- gtkdoc
 * 30/5/13
 * 	- rewrite as a class
 * 	- add --band option, remove im_msb_band()
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H */
#include <vips/intl.h>

#include <vips/vips.h>

#include "pconversion.h"

#include "bandary.h"

typedef struct _VipsMsb {
	VipsConversion parent_instance;

	/* Params.
	 */
	VipsImage *in;
	int band; 

	/* Initial input offset.
	 */
	int offset;

	/* Input step.
	 */
	int instep;

	/* Need to convert signed to unsgned.
	 */
	gboolean sign;

} VipsMsb;

typedef VipsConversionClass VipsMsbClass;

G_DEFINE_TYPE( VipsMsb, vips_msb, VIPS_TYPE_CONVERSION );

static int
vips_msb_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsMsb *msb = (VipsMsb *) b;
	VipsConversion *conversion = (VipsConversion *) msb;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );
	int sz = r->width * conversion->out->Bands;

	int x, y, i;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	for( y = to; y < bo; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); 
		VipsPel *q = VIPS_REGION_ADDR( or, le, y ); 

		if( msb->in->Coding == VIPS_CODING_LABQ &&
			msb->band == -1 ) {
			/* LABQ, no sub-band select.
			 */
			for( x = 0; x < r->width; x++ ) {
				q[0] = p[0];
				q[1] = 0x80 ^ p[1];
				q[2] = 0x80 ^ p[2];

				q += 4;
				p += 3;
			}
		}
		else if( msb->sign ) {
			/* Copy, converting signed to unsigned.
			 */
			p += msb->offset;
			for( i = 0; i < sz; i++ ) {
				q[i] = 0x80 ^ *p;

				p += msb->instep;
			}
		}
		else {
			/* Just pick out bytes. 
			 */
			p += msb->offset;
			for( i = 0; i < sz; i++ ) {
				q[i] = *p;

				p += msb->instep;
			}
		}
	}

	return( 0 );
}

static int
vips_msb_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = (VipsConversion *) object;
	VipsMsb *msb = (VipsMsb *) object;

	int vbands;

	if( VIPS_OBJECT_CLASS( vips_msb_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_coding_noneorlabq( class->nickname, msb->in ) ||
		vips_check_int( class->nickname, msb->in ) )
		return( -1 );

	/* Effective number of bands this image has.
	 */
	vbands = msb->in->Coding == VIPS_CODING_LABQ ? 
		3 : msb->in->Bands;

	if( msb->band > vbands - 1 ) {
		vips_error( class->nickname, "%s", _( "bad band" ) );
		return( -1 );
	}

	/* Step to next input element.
	 */
	msb->instep = VIPS_IMAGE_SIZEOF_ELEMENT( msb->in );

	/* Offset into first band element of high order byte.
	 */
	msb->offset = vips_amiMSBfirst() ?  
		0 : VIPS_IMAGE_SIZEOF_ELEMENT( msb->in ) - 1;

	/* If we're picking out a band, they need scaling up.
	 */
	if( msb->band != -1 ) {
		msb->offset += VIPS_IMAGE_SIZEOF_ELEMENT( msb->in ) * 
			msb->band;
		msb->instep *= msb->in->Bands;
	}

	/* May need to flip sign if we're picking out a band from labq.
	 */
	if( msb->in->Coding == VIPS_CODING_LABQ &&
		msb->band > 0 )
		msb->sign = TRUE;
	if( msb->in->Coding == VIPS_CODING_NONE &&
		!vips_band_format_isuint( msb->in->BandFmt ) )
		msb->sign = TRUE;

	if( msb->band == -1 &&
		msb->in->BandFmt == VIPS_FORMAT_UCHAR )
		return( vips_image_write( msb->in, conversion->out ) );
	if( msb->band == 0 &&
		msb->in->Bands == 1 &&
		msb->in->BandFmt == VIPS_FORMAT_UCHAR )
		return( vips_image_write( msb->in, conversion->out ) );

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, msb->in, NULL ) )
		return( -1 );

	if( msb->band != -1 )
		conversion->out->Bands = 1;
	else 
		conversion->out->Bands = vbands;
	conversion->out->BandFmt = VIPS_FORMAT_UCHAR;
	conversion->out->Coding = VIPS_CODING_NONE;
	if( conversion->out->Bands == 1 ) 
		conversion->out->Type = VIPS_INTERPRETATION_B_W;
	else
		conversion->out->Type = VIPS_INTERPRETATION_MULTIBAND;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_msb_gen, vips_stop_one, msb->in, msb ) )
		return( -1 );

	return( 0 );
}

static void
vips_msb_class_init( VipsMsbClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "msb";
	vobject_class->description = 
		_( "pick most-significant byte from an image" );
	vobject_class->build = vips_msb_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMsb, in ) );

	VIPS_ARG_INT( class, "band", 3, 
		_( "Band" ), 
		_( "Band to msb" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMsb, band ),
		0, 100000000, 0 );

}

static void
vips_msb_init( VipsMsb *msb )
{
	msb->band = -1;
}

/**
 * vips_msb:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @band: msb just this band
 *
 * Turn any integer image to 8-bit unsigned char by discarding all but the most
 * significant byte. Signed values are converted to unsigned by adding 128.
 *
 * Use @band to make a one-band 8-bit image. 
 *
 * This operator also works for LABQ coding.
 *
 * See also: vips_scale(), vips_cast().
 * 
 * Returns: 0 on success, -1 on error.
 */
int
vips_msb( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "msb", ap, in, out );
	va_end( ap );

	return( result );
}

