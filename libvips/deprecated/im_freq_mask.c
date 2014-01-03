/* Create masks and filter with them.
 *
 * Copyright: N. Dessipris 1991,
 * Written on: Nov 1991
 * Updated on: Dec 1991
 * 20/9/95 JC
 *	- modernised 
 * 22/3/10
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>
#include <stdarg.h>

#include <vips/vips.h>
#include <vips/internal.h>

/* Make a mask image.
 */
static int 
build_freq_mask( IMAGE *out, int xs, int ys, ImMaskType flag, va_list ap )
{
	/* May be fewer than 4 args ... but extract them all anyway. Should be
	 * safe.
	 */
	double p0 = va_arg( ap, double );
	double p1 = va_arg( ap, double );
	double p2 = va_arg( ap, double );
	double p3 = va_arg( ap, double );
	double p4 = va_arg( ap, double );

	VipsImage *t;

	switch( flag ) {
	case IM_MASK_IDEAL_HIGHPASS:
		if( vips_mask_ideal( &t, xs, ys, p0,
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_IDEAL_LOWPASS:
		if( vips_mask_ideal( &t, xs, ys, p0,
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_BUTTERWORTH_HIGHPASS:
		if( vips_mask_butterworth( &t, xs, ys, p0, p1, p2,
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_BUTTERWORTH_LOWPASS:
		if( vips_mask_butterworth( &t, xs, ys, p0, p1, p2,
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_GAUSS_HIGHPASS:
		if( vips_mask_gaussian( &t, xs, ys, p0, p1, 
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_GAUSS_LOWPASS:
		if( vips_mask_gaussian( &t, xs, ys, p0, p1, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_IDEAL_RINGPASS:
		if( vips_mask_ideal_ring( &t, xs, ys, p0, p1, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_IDEAL_RINGREJECT:
		if( vips_mask_ideal_ring( &t, xs, ys, p0, p1, 
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_BUTTERWORTH_RINGPASS:
		if( vips_mask_butterworth_ring( &t, xs, ys, p0, p1, p2, p3,
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_BUTTERWORTH_RINGREJECT:
		if( vips_mask_butterworth_ring( &t, xs, ys, p0, p1, p2, p3,
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_GAUSS_RINGPASS:
		if( vips_mask_gaussian_ring( &t, xs, ys, p0, p1, p2, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_GAUSS_RINGREJECT:
		if( vips_mask_gaussian_ring( &t, xs, ys, p0, p1, p2, 
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_FRACTAL_FLT:
		if( vips_mask_fractal( &t, xs, ys, p0, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_IDEAL_BANDPASS:
		if( vips_mask_ideal_band( &t, xs, ys, p0, p1, p2, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_IDEAL_BANDREJECT:
		if( vips_mask_ideal_band( &t, xs, ys, p0, p1, p2, 
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_BUTTERWORTH_BANDPASS:
		if( vips_mask_butterworth_band( &t, xs, ys, p0, p1, p2, p3, p4,
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_BUTTERWORTH_BANDREJECT:
		if( vips_mask_butterworth_band( &t, xs, ys, p0, p1, p2, p3, p4,
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_GAUSS_BANDPASS:
		if( vips_mask_gaussian_band( &t, xs, ys, p0, p1, p2, p3, 
			NULL ) )
			return( -1 );
		break;

	case IM_MASK_GAUSS_BANDREJECT:
		if( vips_mask_gaussian_band( &t, xs, ys, p0, p1, p2, p3, 
			"reject", TRUE, 
			NULL ) )
			return( -1 );
		break;

	default:
	       im_error( "im_freq_mask", "%s", _( "unimplemented mask type" ) );
	       return( -1 );
	}

	if( im_copy( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_flt_image_freq( IMAGE *in, IMAGE *out, ImMaskType flag, ... )
{
        IMAGE *mask = im_open_local( out, "tempmask", "p" );
	va_list ap;

        if( !mask )
		return( -1 );

	/* Generate mask.
	 */
        va_start( ap, flag );
        if( build_freq_mask( mask, in->Xsize, in->Ysize, flag, ap ) )
                return( -1 );
        va_end( ap );

        if( im_freqflt( in, mask, out ) )
                return( -1 );

        return( 0 );
}

int
im_create_fmask( IMAGE *out, int xsize, int ysize, ImMaskType flag, ... )
{
	va_list ap;

	va_start( ap, flag );
	if( build_freq_mask( out, xsize, ysize, flag, ap ) )
		return( -1 );
	va_end( ap );

	return( 0 );
}
