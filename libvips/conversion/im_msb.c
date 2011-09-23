/* im_msb
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

/** HEADERS **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H */
#include <vips/intl.h>

#include <vips/vips.h>

typedef struct _Msb {
	size_t index;
	size_t width;
	size_t repeat;
} Msb;

static void
byte_select( unsigned char *in, unsigned char *out, int n, Msb *msb )
{
	unsigned char *stop = out + n * msb->repeat;

	for( in += msb->index; out < stop; in += msb->width, ++out )
		*out = *in;
}

static void
byte_select_flip( unsigned char *in, unsigned char *out, int n, Msb *msb )
{
	unsigned char *stop = out + n * msb->repeat;

	for( in += msb->index; out < stop; in += msb->width, ++out )
		*out = 0x80 ^ *in;
}

static void
msb_labq( unsigned char *in, unsigned char *out, int n )
{
	unsigned char *stop = in + (n << 2);

	for( ; in < stop; in += 4, out += 3 ) {
		out[0] = in[0];
		out[1] = 0x80 ^ in[1];
		out[2] = 0x80 ^ in[2];
	}
}

/**
 * im_msb:
 * @in: input image
 * @out: output image
 *
 * Turn any integer image to 8-bit unsigned char by discarding all but the most
 * significant byte.
 * Signed values are converted to unsigned by adding 128.
 *
 * This operator also works for LABQ coding.
 *
 * See also: im_msb_band().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_msb( IMAGE *in, IMAGE *out )
{
	Msb *msb;
	im_wrapone_fn func;

	if( in->Coding == IM_CODING_NONE &&
		in->BandFmt == IM_BANDFMT_UCHAR )
		return( im_copy( in, out ) );

	if( im_piocheck( in, out ) ||
		!(msb = IM_NEW( out, Msb )) )
		return( -1 );

	if( in->Coding == IM_CODING_NONE ) {
		if( im_check_int( "im_msb", in ) ) 
			return( -1 );

		msb->width = IM_IMAGE_SIZEOF_ELEMENT( in );
		msb->index = im_amiMSBfirst() ? 0 : msb->width - 1;
		msb->repeat = in->Bands;

		if( vips_bandfmt_isuint( in->BandFmt ) )
			func = (im_wrapone_fn) byte_select;
		else
			func = (im_wrapone_fn) byte_select_flip;
	}
	else if( IM_CODING_LABQ == in->Coding )
		func = (im_wrapone_fn) msb_labq;
	else {
		im_error( "im_msb", "%s", _( "unknown coding" ) );
		return( -1 );
	}

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->BandFmt = IM_BANDFMT_UCHAR;
	out->Coding = IM_CODING_NONE;

	return( im_wrapone( in, out, func, msb, NULL ) );
}

/**
 * im_msb_band:
 * @in: input image
 * @out: output image
 * @band: select this band
 *
 * Turn any integer image to a single-band 8-bit unsigned char by discarding 
 * all but the most significant byte from the selected band. 
 * Signed values are converted to unsigned by adding 128.
 *
 * This operator also works for LABQ coding.
 *
 * See also: im_msb_band().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_msb_band( IMAGE *in, IMAGE *out, int band )
{
	Msb *msb;
	im_wrapone_fn func;

	if( band < 0 ) {
		im_error( "im_msb_band", "%s", _( "bad arguments" ) );
		return( -1 );
	}

	if( im_piocheck( in, out ) ||
		!(msb = IM_NEW( out, Msb )) )
		return( -1 );

	if( in->Coding == IM_CODING_NONE ) {
		if( im_check_int( "im_msb_band", in ) ) 
			return( -1 );

		if( band >= in->Bands ) {
			im_error( "im_msb_band", "%s", 
				_( "image does not have that many bands" ) );
			return( -1 );
		}

		msb->width = IM_IMAGE_SIZEOF_ELEMENT( in );
		msb->index = im_amiMSBfirst() ? 
			msb->width * band : msb->width * (band + 1) - 1;
		msb->repeat = 1;

		if( vips_bandfmt_isuint( in->BandFmt ) )
			func = (im_wrapone_fn) byte_select;
		else
			func = (im_wrapone_fn) byte_select_flip;
	}
	else if( IM_CODING_LABQ == in->Coding ) {
		if( band > 2 ) {
			im_error( "im_msb_band", "%s", 
				_( "image does not have that many bands" ) );
			return( -1 );
		}
		msb->width = 4;
		msb->repeat = 1;
		msb->index = band;

		if( band )
			func = (im_wrapone_fn) byte_select_flip;
		else
			func = (im_wrapone_fn) byte_select;
	}
	else {
		im_error( "im_msb", "%s", _( "unknown coding" ) );
		return( -1 );
	}

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->BandFmt = IM_BANDFMT_UCHAR;
	out->Coding = IM_CODING_NONE;
	out->Bands = 1;

	return( im_wrapone( in, out, func, msb, NULL ) );
}
