/* histogram normalisation
 *
 * Author: N. Dessipris
 * Written on: 02/08/1990
 * 24/5/95 JC
 *	- tidied up and ANSIfied
 * 20/7/95 JC
 *	- smartened up again
 *	- now works for hists >256 elements
 * 3/3/01 JC
 *	- broken into cum and norm ... helps im_histspec()
 *	- better behaviour for >8 bit hists
 * 31/10/05 JC
 * 	- was broken for vertical histograms, gah
 * 	- neater im_histnorm()
 * 23/7/07
 * 	- eek, off by 1 for more than 1 band hists
 * 12/5/08
 * 	- histcum works for signed hists now as well
 * 24/3/10
 * 	- gtkdoc
 * 	- small cleanups
 * 12/8/13	
 * 	- redone im_histcum() as a class, vips_hist_cum()
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

#include <vips/vips.h>

#include "phistogram.h"

typedef VipsHistogram VipsHistCum;
typedef VipsHistogramClass VipsHistCumClass;

G_DEFINE_TYPE( VipsHistCum, vips_hist_cum, VIPS_TYPE_HISTOGRAM );

#define ACCUMULATE( ITYPE, OTYPE ) { \
	for( b = 0; b < nb; b++ ) { \
		ITYPE *p = (ITYPE *) in; \
		OTYPE *q = (OTYPE *) out; \
		OTYPE total; \
		\
		total = 0; \
		for( x = b; x < mx; x += nb ) { \
			total += p[x]; \
			q[x] = total; \
		} \
	} \
}

static void
vips_hist_cum_buffer( VipsHistogram *histogram, 
	VipsPel *out, VipsPel *in, int width )
{
	const int bands = vips_image_get_bands( histogram->in );
	const int nb = vips_bandfmt_iscomplex( histogram->in->BandFmt ) ? 
		bands * 2 : bands;
	int mx = width * nb;

	int x, b; 

	switch( vips_image_get_format( histogram->in ) ) {
        case VIPS_FORMAT_CHAR: 		
		ACCUMULATE( signed char, signed int ); break; 
        case VIPS_FORMAT_UCHAR: 		
		ACCUMULATE( unsigned char, unsigned int ); break; 
        case VIPS_FORMAT_SHORT: 		
		ACCUMULATE( signed short, signed int ); break; 
        case VIPS_FORMAT_USHORT: 	
		ACCUMULATE( unsigned short, unsigned int ); break; 
        case VIPS_FORMAT_INT: 		
		ACCUMULATE( signed int, signed int ); break; 
        case VIPS_FORMAT_UINT: 		
		ACCUMULATE( unsigned int, unsigned int ); break; 

        case VIPS_FORMAT_FLOAT: 		
        case VIPS_FORMAT_COMPLEX:	
		ACCUMULATE( float, float ); break;
        case VIPS_FORMAT_DOUBLE:		
        case VIPS_FORMAT_DPCOMPLEX:	
		ACCUMULATE( double, double ); break;

        default:
		g_assert( 0 );
        }
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static const VipsBandFormat vips_bandfmt_hist_cum[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UI, I,  UI, I,  UI, I,  F,  F,  D,  D 
};

static void
vips_hist_cum_class_init( VipsHistCumClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsHistogramClass *hclass = VIPS_HISTOGRAM_CLASS( class );

	object_class->nickname = "hist_cum";
	object_class->description = _( "form cumulative histogram" );

	hclass->format_table = vips_bandfmt_hist_cum;
	hclass->process = vips_hist_cum_buffer;
}

static void
vips_hist_cum_init( VipsHistCum *hist_cum )
{
}

/**
 * vips_hist_cum:
 * @in: input image
 * @out: output image
 *
 * Form cumulative histogram. 
 *
 * See also: vips_hist_norm().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_cum( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_cum", ap, in, out );
	va_end( ap );

	return( result );
}
