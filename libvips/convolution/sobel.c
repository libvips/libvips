/* Sobel edge detector
 * 
 * 2/2/18
 * 	- from vips_sobel()
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

typedef struct _VipsSobel {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	/* Need an image vector for start_many.
	 */
	VipsImage *args[3];
} VipsSobel;

typedef VipsOperationClass VipsSobelClass;

G_DEFINE_TYPE( VipsSobel, vips_sobel, VIPS_TYPE_OPERATION );

static int
vips_sobel_uchar_gen( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRegion **in = (VipsRegion **) vseq;
	VipsRect *r = &or->valid;
	int sz = r->width * in[0]->im->Bands;

	int x, y;

	if( vips_reorder_prepare_many( or->im, in, r ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *p1 = (VipsPel * restrict) 
			VIPS_REGION_ADDR( in[0], r->left, r->top + y );
		VipsPel *p2 = (VipsPel * restrict) 
			VIPS_REGION_ADDR( in[1], r->left, r->top + y );
		VipsPel *q = (VipsPel * restrict) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );

		for( x = 0; x < sz; x++ ) {
			int v1 = 2 * (p1[x] - 128);
			int v2 = 2 * (p2[x] - 128);
			int v = VIPS_ABS( v1 ) + VIPS_ABS( v2 );

			q[x] = v > 255 ? 255 : v;
		}
	}

	return( 0 );
}

/* Fast uchar path.
 */
static int
vips_sobel_build_uchar( VipsSobel *sobel )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( sobel ), 20 );

	g_info( "vips_sobel: uchar path" ); 

	/* Sobel is separable, but it's so small there's no speed to be gained,
	 * and doing it one pass lets us keep more precision.
	 *
	 * Divide the result by 2 to prevent overflow, since our result will be
	 * just 8 bits.
	 */
	t[1] = vips_image_new_matrixv( 3, 3, 
		 1.0,  2.0,  1.0,
		 0.0,  0.0,  0.0,
		-1.0, -2.0, -1.0 );
	vips_image_set_double( t[1], "offset", 128.0 ); 
	vips_image_set_double( t[1], "scale", 2.0 ); 
	if( vips_conv( sobel->in, &t[3], t[1], 
		"precision", VIPS_PRECISION_INTEGER,
		NULL ) )
		return( -1 );

	if( vips_rot90( t[1], &t[5], NULL ) ||
		vips_conv( sobel->in, &t[7], t[5], 
			"precision", VIPS_PRECISION_INTEGER,
			NULL ) )
		return( -1 );

	g_object_set( sobel, "out", vips_image_new(), NULL ); 

	sobel->args[0] = t[3];
	sobel->args[1] = t[7];
	sobel->args[2] = NULL;
	if( vips_image_pipeline_array( sobel->out, 
		VIPS_DEMAND_STYLE_FATSTRIP, sobel->args ) )
		return( -1 );

	if( vips_image_generate( sobel->out, 
		vips_start_many, vips_sobel_uchar_gen, vips_stop_many, 
		sobel->args, NULL ) )
		return( -1 );

	return( 0 );
}

/* Works for any format, but slower.
 */
static int
vips_sobel_build_float( VipsSobel *sobel )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( sobel ), 20 );

	g_info( "vips_sobel: float path" ); 

	t[1] = vips_image_new_matrixv( 3, 3, 
		 1.0,  2.0,  1.0,
		 0.0,  0.0,  0.0,
		-1.0, -2.0, -1.0 );
	if( vips_rot90( t[1], &t[2], NULL ) ||
		vips_conv( sobel->in, &t[3], t[1], NULL ) ||
		vips_conv( sobel->in, &t[7], t[2], NULL ) )
		return( -1 );

	if( vips_abs( t[3], &t[9], NULL ) ||
		vips_abs( t[7], &t[10], NULL ) ||
		vips_add( t[9], t[10], &t[11], NULL ) ||
		vips_cast( t[11], &t[12], sobel->in->BandFmt, NULL ) )
		return( -1 ); 

	g_object_set( sobel, "out", vips_image_new(), NULL ); 

	if( vips_image_write( t[12], sobel->out ) )
		return( -1 );

	return( 0 );
}

static int
vips_sobel_build( VipsObject *object )
{
	VipsSobel *sobel = (VipsSobel *) object;

	if( sobel->in->BandFmt == VIPS_FORMAT_UCHAR ) {
		if( vips_sobel_build_uchar( sobel ) )
			return( -1 ); 
	}
	else {
		if( vips_sobel_build_float( sobel ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_sobel_class_init( VipsSobelClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "sobel";
	object_class->description = _( "Sobel edge detector" );
	object_class->build = vips_sobel_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSobel, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsSobel, out ) );

}

static void
vips_sobel_init( VipsSobel *sobel )
{
}

/**
 * vips_sobel: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Simple Sobel edge detector.
 *
 * See also: vips_canny().
 * 
 * Returns: 0 on success, -1 on error.
 */
int 
vips_sobel( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sobel", ap, in, out );  
	va_end( ap );

	return( result );
}
