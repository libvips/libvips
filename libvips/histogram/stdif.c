/* statistical difference 
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 
 * 6/8/93 JC
 *	- now works for odd window sizes
 *	- ANSIfication
 * 25/5/95 JC
 *	- new IM_ARRAY() macro
 * 25/1/96 JC
 *	- im_lhisteq() adapted to make new im_stdif()
 *	- now partial, plus rolling window
 *	- 5x faster, amazingly
 *	- works
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
 * 25/3/10
 * 	- gtkdoc
 * 	- small cleanups
 * 10/8/13	
 * 	- wrapped as a class using hist_local.c
 * 	- many bands
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
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <vips/vips.h>

typedef struct _VipsStdif {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	int width;
	int height;

	double a;
	double m0;
	double b;
	double s0;

} VipsStdif;

typedef VipsOperationClass VipsStdifClass;

G_DEFINE_TYPE( VipsStdif, vips_stdif, VIPS_TYPE_OPERATION );

/* How ugly and stupid.
 */
#define MAX_BANDS (100)

static int
vips_stdif_generate( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRect *r = &or->valid;
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsStdif *stdif = (VipsStdif *) b;
	int bands = in->Bands; 
	int npel = stdif->width * stdif->width;

	VipsRect irect;
	int y;
	int lsk;
	int centre;			/* Offset to move to centre of window */

	/* What part of ir do we need?
	 */
	irect.left = or->valid.left;
	irect.top = or->valid.top;
	irect.width = or->valid.width + stdif->width;
	irect.height = or->valid.height + stdif->height;
	if( vips_region_prepare( ir, &irect ) )
		return( -1 );

	lsk = VIPS_REGION_LSKIP( ir );
	centre = lsk * (stdif->height / 2) + stdif->width / 2;

	for( y = 0; y < r->height; y++ ) {
		/* Get input and output pointers for this line.
		 */
		VipsPel *p = VIPS_REGION_ADDR( ir, r->left, r->top + y );
		VipsPel *q = VIPS_REGION_ADDR( or, r->left, r->top + y );

		double f1 = stdif->a * stdif->m0;
		double f2 = 1.0 - stdif->a;
		double f3 = stdif->b * stdif->s0;

		VipsPel *p1;
		int x, i, j, b;

		/* We will get int overflow for windows larger than about 256
		 * x 256, sadly.
		 */
		unsigned int sum[MAX_BANDS];
		unsigned int sum2[MAX_BANDS];

		/* Find sum, sum of squares for the start of this line.
		 */
		for( b = 0; b < bands; b++ ) {
			memset( sum, 0, bands * sizeof( unsigned int ) );
			memset( sum2, 0, bands * sizeof( unsigned int ) );
		}
		p1 = p;
		for( j = 0; j < stdif->height; j++ ) {
			i = 0;
			for( x = 0; x < stdif->width; x++ ) {
				for( b = 0; b < bands; b++ ) { 
					int t = p1[i++];

					sum[b] += t;
					sum2[b] += t * t;
				}
			}

			p1 += lsk;
		}

		/* Loop for output pels.
		 */
		for( x = 0; x < r->width; x++ ) {
			for( b = 0; b < bands; b++ ) { 
				/* Find stats.
				 */
				double mean = (double) sum[b] / npel;
				double var = (double) sum2[b] / npel - 
					(mean * mean);
				double sig = sqrt( var );

				/* Transform.
				 */
				double res = f1 + f2 * mean + 
					((double) p[centre] - mean) * 
					(f3 / (stdif->s0 + stdif->b * sig));

				/* And write.
				 */
				if( res < 0.0 )
					*q++ = 0;
				else if( res >= 256.0 )
					*q++ = 255;
				else
					*q++ = res + 0.5;

				/* Adapt sums - remove the pels from the left 
				 * hand column, add in pels for a new 
				 * right-hand column.
				 */
				p1 = p;
				for( j = 0; j < stdif->height; j++ ) {
					int t1 = p1[0];
					int t2 = p1[bands * stdif->width];

					sum[b] -= t1;
					sum2[b] -= t1 * t1;

					sum[b] += t2;
					sum2[b] += t2 * t2;

					p1 += lsk;
				}

				p += 1;
			}
		}
	}

	return( 0 );
}

static int
vips_stdif_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStdif *stdif = (VipsStdif *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 3 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_stdif_parent_class )->build( object ) )
		return( -1 );

	in = stdif->in; 

	if( vips_check_uncoded( class->nickname, in ) ||
		vips_check_format( class->nickname, in, VIPS_FORMAT_UCHAR ) )
		return( -1 );

	if( stdif->width > in->Xsize || 
		stdif->height > in->Ysize ) {
		vips_error( class->nickname, "%s", _( "window too large" ) );
		return( -1 );
	}
	if( in->Bands > MAX_BANDS ) {
		vips_error( class->nickname, "%s", _( "too many bands" ) );
		return( -1 );
	}

	/* Expand the input. 
	 */
	if( vips_embed( in, &t[0], 
		stdif->width / 2, stdif->height / 2, 
		in->Xsize + stdif->width - 1, in->Ysize + stdif->height - 1,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[0];

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( vips_image_copy_fields( stdif->out, in ) )
		return( -1 );
	stdif->out->Xsize -= stdif->width - 1;
	stdif->out->Ysize -= stdif->height - 1;

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	vips_demand_hint( stdif->out, 
		VIPS_DEMAND_STYLE_FATSTRIP, in, NULL );

	if( vips_image_generate( stdif->out, 
		vips_start_one, 
		vips_stdif_generate, 
		vips_stop_one, 
		in, stdif ) )
		return( -1 );

	stdif->out->Xoffset = 0;
	stdif->out->Yoffset = 0;

	return( 0 );
}

static void
vips_stdif_class_init( VipsStdifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "stdif";
	object_class->description = _( "statistical difference" );
	object_class->build = vips_stdif_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsStdif, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsStdif, out ) );

	/* Windows larger than 256x256 will overflow sum2, see above.
	 */
	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Window width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsStdif, width ),
		1, 256, 11 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Window height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsStdif, height ),
		1, 256, 11 );

	VIPS_ARG_DOUBLE( class, "a", 2, 
		_( "Mean weight" ), 
		_( "Weight of new mean" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsStdif, a ),
		0.0, 1.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "m0", 2, 
		_( "Mean" ), 
		_( "New mean" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsStdif, m0 ),
		-INFINITY, INFINITY, 128 );

	VIPS_ARG_DOUBLE( class, "b", 2, 
		_( "Deviation weight" ), 
		_( "Weight of new deviation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsStdif, b ),
		0.0, 2.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "s0", 2, 
		_( "Deviation" ), 
		_( "New deviation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsStdif, s0 ),
		-INFINITY, INFINITY, 50 );

}

static void
vips_stdif_init( VipsStdif *stdif )
{
	stdif->width = 11;
	stdif->height = 11;
	stdif->a = 0.5;
	stdif->m0 = 128.0;
	stdif->b = 0.5;
	stdif->s0 = 50.0;
}

/**
 * vips_stdif:
 * @in: input image
 * @out: output image
 * @width: width of region
 * @height: height of region
 *
 * Optional arguments:
 *
 * @a: weight of new mean
 * @m0: target mean
 * @b: weight of new deviation
 * @s0: target deviation
 *
 * vips_stdif() preforms statistical differencing according to the formula
 * given in page 45 of the book "An Introduction to Digital Image 
 * Processing" by Wayne Niblack. This transformation emphasises the way in 
 * which a pel differs statistically from its neighbours. It is useful for 
 * enhancing low-contrast images with lots of detail, such as X-ray plates.
 *
 * At point (i,j) the output is given by the equation:
 *
 * vout(i,j) = @a * @m0 + (1 - @a) * meanv + 
 *       (vin(i,j) - meanv) * (@b * @s0) / (@s0 + @b * stdv)
 *
 * Values @a, @m0, @b and @s0 are entered, while meanv and stdv are the values
 * calculated over a moving window of size @width, @height centred on pixel 
 * (i,j). @m0 is the new mean, @a is the weight given to it. @s0 is the new 
 * standard deviation, @b is the weight given to it. 
 *
 * Try:
 *
 * vips stdif $VIPSHOME/pics/huysum.v fred.v 0.5 128 0.5 50 11 11
 *
 * The operation works on one-band uchar images only, and writes a one-band 
 * uchar image as its result. The output image has the same size as the 
 * input.
 *
 * See also: vips_hist_local().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_stdif( VipsImage *in, VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "stdif", ap, in, out, width, height );
	va_end( ap );

	return( result );
}

