/* Canny edge detector
 * 
 * 2/2/18
 * 	- from vips_canny()
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

typedef struct _VipsCanny {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	gdouble sigma; 

	/* Need an image vector for start_many.
	 */
	VipsImage *args[3];
} VipsCanny;

typedef VipsOperationClass VipsCannyClass;

G_DEFINE_TYPE( VipsCanny, vips_canny, VIPS_TYPE_OPERATION );

static int
vips_canny_polar_generate( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRegion **in = (VipsRegion **) vseq;
	VipsRect *r = &or->valid;
	VipsImage *Gx = in[0]->im;

	int x, y, band; 

	if( vips_reorder_prepare_many( or->im, in, r ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *p1 = (VipsPel * restrict) 
			VIPS_REGION_ADDR( in[0], r->left, r->top + y );
		VipsPel *p2 = (VipsPel * restrict) 
			VIPS_REGION_ADDR( in[1], r->left, r->top + y );
		VipsPel *q = (VipsPel * restrict) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );

		for( x = 0; x < r->width; x++ ) {
			for( band = 0; band < Gx->Bands; band++ ) { 
				int x = p1[band] - 128;
				int y = p2[band] - 128;
				int a = VIPS_DEG( atan2( x, y ) );

				q[0] = sqrt( x * x + y * y );
				q[1] = ((a + 360 + 22) / 45) & 0x3;

				q += 2;
			}

			p1 += Gx->Bands;
			p2 += Gx->Bands;
		}
	}

	return( 0 );
}

/* Calculate G/theta from Gx/Gy -- rather like rect -> polar, except that we
 * constrain theta to 0/45/90/135, which we code as 0/1/2/3, and we don't care
 * about the sign of G.
 *
 * Theta values:
 *
 *   3 | 0 | 1
 *   --+---+--
 *   2 | x | 2
 *   --+---+--
 *   1 | 0 | 3
 */
static int
vips_canny_polar( VipsImage **args, VipsImage **out )
{
	*out = vips_image_new();
	if( vips_image_pipeline_array( *out, 
		VIPS_DEMAND_STYLE_THINSTRIP, args ) )
		return( -1 );
	(*out)->Bands *= 2;

	if( vips_image_generate( *out, 
		vips_start_many, vips_canny_polar_generate, vips_stop_many, 
		args, NULL ) )
		return( -1 );

	return( 0 );
}

static int
vips_canny_nonmax_generate( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRegion *in = (VipsRegion *) vseq;
	VipsRect *r = &or->valid;
	VipsImage *im = in->im;

	VipsRect rect;
	int x, y, band; 
	int lsk;
	int psk;
	int offseta[4];
	int offsetb[4];

	rect = *r;
	rect.width += 2;
	rect.height += 2;
	if( vips_region_prepare( in, &rect ) )
		return( -1 );
	lsk = VIPS_REGION_LSKIP( in ); 
	psk = VIPS_IMAGE_SIZEOF_PEL( im ); 

	/* For each of the four directions, the offset to get to that pixel
	 * from the top-left of our 3x3.
	 */
	offseta[0] = psk;
	offsetb[0] = psk + 2 * lsk;
	offseta[1] = 2 * psk;
	offsetb[1] = 2 * lsk;
	offseta[2] = 2 * psk + lsk;
	offsetb[2] = lsk;
	offseta[3] = 0;
	offsetb[3] = 2 * psk + 2 * lsk;

	for( y = 0; y < r->height; y++ ) {
		VipsPel *p = (VipsPel * restrict) 
			VIPS_REGION_ADDR( in, r->left, r->top + y );
		VipsPel *q = (VipsPel * restrict) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );

		for( x = 0; x < r->width; x++ ) {
			for( band = 0; band < im->Bands; band++ ) { 
				int G = p[lsk + psk];
				int theta = p[lsk + psk + 1];
				VipsPel low = p[offseta[theta]];
				VipsPel high = p[offsetb[theta]];

				/* Set G to 0 if it's not the local maxima in
				 * the direction of the gradient. 
				 */
				if( G < low ||
					G < high )
					G = 0;

				q[band] = G;

				p += 2;
			}

			q += im->Bands;
		}
	}

	return( 0 );
}

/* Remove non-maximal edges. At each point, compare the G to the G in either
 * direction and 0 it if it's not the largest.
 */
static int
vips_canny_nonmax( VipsImage *in, VipsImage **out )
{
	*out = vips_image_new();
	if( vips_image_pipelinev( *out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );
	(*out)->Bands /= 2;
	(*out)->Xsize -= 2;
	(*out)->Ysize -= 2;

	if( vips_image_generate( *out, 
		vips_start_one, vips_canny_nonmax_generate, vips_stop_one, 
		in, NULL ) )
		return( -1 );

	return( 0 );
}

static int
vips_canny_build( VipsObject *object )
{
	VipsCanny *canny = (VipsCanny *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 20 );

	VipsImage *in;
	VipsImage *Gx;
	VipsImage *Gy;

	if( VIPS_OBJECT_CLASS( vips_canny_parent_class )->build( object ) )
		return( -1 );

	in = canny->in;

	if( vips_gaussblur( in, &t[0], canny->sigma, NULL ) )
		return( -1 );
	in = t[0];

	/* Separated Sobel gives Gx / Gy. Aim for vector path.
	 */
	t[1] = vips_image_new_matrixv( 1, 3, 1.0, 2.0, 1.0 );
	t[2] = vips_image_new_matrixv( 3, 1, 1.0, 0.0, -1.0 );
	vips_image_set_double( t[2], "offset", 128.0 ); 
	if( vips_conv( in, &t[3], t[1], 
		"precision", VIPS_PRECISION_INTEGER,
		NULL ) ||
		vips_conv( t[3], &t[4], t[2], 
			"precision", VIPS_PRECISION_INTEGER,
			NULL ) )
		return( -1 );
	Gx = t[4];

	t[5] = vips_image_new_matrixv( 3, 1, 1.0, 2.0, 1.0 );
	t[6] = vips_image_new_matrixv( 1, 3, 1.0, 0.0, -1.0 );
	vips_image_set_double( t[6], "offset", 128.0 ); 
	if( vips_conv( in, &t[7], t[5], 
		"precision", VIPS_PRECISION_INTEGER,
		NULL ) ||
		vips_conv( t[7], &t[8], t[6], 
			"precision", VIPS_PRECISION_INTEGER,
			NULL ) )
		return( -1 );
	Gy = t[8];

	/* Form (G, theta), with theta coded.
	 */
	canny->args[0] = Gx;
	canny->args[1] = Gy;
	canny->args[2] = NULL;
	if( vips_canny_polar( canny->args, &t[9] ) )
		return( -1 ); 
	in = t[9];

	/* Expand by two pixels all around, then thin.
	 */
	if( vips_embed( in, &t[10], 1, 1, in->Xsize, in->Ysize,
		"extend", VIPS_EXTEND_COPY,
		NULL ) ||
		vips_canny_nonmax( t[10], &t[11] ) )
		return( -1 );
	in = t[11];

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( vips_image_write( in, canny->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_canny_class_init( VipsCannyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "canny";
	object_class->description = _( "gaussian blur" );
	object_class->build = vips_canny_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCanny, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsCanny, out ) );

	VIPS_ARG_DOUBLE( class, "sigma", 10, 
		_( "Sigma" ), 
		_( "Sigma of Gaussian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCanny, sigma ),
		0.01, 1000, 1.4 );

}

static void
vips_canny_init( VipsCanny *canny )
{
	canny->sigma = 1.4; 
}

/**
 * vips_canny: (method)
 * @in: input image
 * @out: (out): output image
 * @sigma: how large a mask to use
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @sigma: %gdouble, sigma for gaussian blur
 *
 * See also: vips_gaussblur().
 * 
 * Returns: 0 on success, -1 on error.
 */
int 
vips_canny( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "canny", ap, in, out );  
	va_end( ap );

	return( result );
}
