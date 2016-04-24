/* subsample
 *
 * 3/7/95 JC
 *	- adapted from im_shrink()
 * 3/8/02 JC
 *	- fall back to im_copy() for x/y factors == 1
 * 21/4/08
 * 	- don't fall back to pixel-wise shrinks for smalltile, it kills
 * 	  performance, just bring VIPS_MAX_WIDTH down instead
 * 1/2/10
 * 	- gtkdoc
 * 1/6/13
 * 	- redo as a class
 * 2/11/13
 * 	- add @point to force point sample mode
 * 22/1/16
 * 	- remove SEQUENTIAL hint, it confuses vips_sequential()
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

#include <vips/vips.h>

#include "pconversion.h"

typedef struct _VipsSubsample {
	VipsConversion parent_instance;

	VipsImage *in;
	int xfac;	
	int yfac;
	gboolean point;

} VipsSubsample;

typedef VipsConversionClass VipsSubsampleClass;

G_DEFINE_TYPE( VipsSubsample, vips_subsample, VIPS_TYPE_CONVERSION );

/* Maximum width of input we ask for.
 */
#define VIPS_MAX_WIDTH (100)

/* Subsample a VipsRegion. We fetch in VIPS_MAX_WIDTH pixel-wide strips, 
 * left-to-right across the input.
 */
static int
vips_subsample_line_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsSubsample *subsample = (VipsSubsample *) b;
	VipsImage *in = (VipsImage *) a;
	VipsRect *r = &or->valid;
	int le = r->left;
	int ri = VIPS_RECT_RIGHT( r );
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );
	int ps = VIPS_IMAGE_SIZEOF_PEL( in );
	int owidth = VIPS_MAX_WIDTH / subsample->xfac;

	VipsRect s;
	int x, y;
	int z, k;

	/* Loop down the region.
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *q = VIPS_REGION_ADDR( or, le, y );
		VipsPel *p;

		/* Loop across the region, in owidth sized pieces.
		 */
		for( x = le; x < ri; x += owidth ) {
			/* How many pixels do we make this time?
			 */
			int ow = VIPS_MIN( owidth, ri - x );

			/* Ask for this many from input ... can save a 
			 * little here!
			 */
			int iw = ow * subsample->xfac - (subsample->xfac - 1);

			/* Ask for input.
			 */
			s.left = x * subsample->xfac;
			s.top = y * subsample->yfac;
			s.width = iw;
			s.height = 1;
			if( vips_region_prepare( ir, &s ) )
				return( -1 );

			/* Append new pels to output.
			 */
			p = VIPS_REGION_ADDR( ir, s.left, s.top );
			for( z = 0; z < ow; z++ ) {
				for( k = 0; k < ps; k++ )
					q[k] = p[k];

				q += ps;
				p += ps * subsample->xfac;
			}
		}
	}

	return( 0 );
}

/* Fetch one pixel at a time ... good for very large shrinks.
 */
static int
vips_subsample_point_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsSubsample *subsample = (VipsSubsample *) b;
	VipsImage *in = (VipsImage *) a;
	VipsRect *r = &or->valid;
	int le = r->left;
	int ri = VIPS_RECT_RIGHT( r );
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);
	int ps = VIPS_IMAGE_SIZEOF_PEL( in );

	VipsRect s;
	int x, y;
	int k;

	/* Loop down the region.
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *q = VIPS_REGION_ADDR( or, le, y );
		VipsPel *p;

		/* Loop across the region, in owidth sized pieces.
		 */
		for( x = le; x < ri; x++ ) {
			/* Ask for input.
			 */
			s.left = x * subsample->xfac;
			s.top = y * subsample->yfac;
			s.width = 1;
			s.height = 1;
			if( vips_region_prepare( ir, &s ) )
				return( -1 );

			/* Append new pels to output.
			 */
			p = VIPS_REGION_ADDR( ir, s.left, s.top );
			for( k = 0; k < ps; k++ )
				q[k] = p[k];
			q += ps;
		}
	}

	return( 0 );
}

static int
vips_subsample_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsSubsample *subsample = (VipsSubsample *) object;

	VipsGenerateFn subsample_fn;

	if( VIPS_OBJECT_CLASS( vips_subsample_parent_class )->build( object ) )
		return( -1 );

	g_assert( subsample->xfac > 0 ); 
	g_assert( subsample->yfac > 0 ); 

	if( subsample->xfac == 1 && 
		subsample->yfac == 1 ) 
		return( vips_image_write( subsample->in, conversion->out ) );
	if( vips_image_pio_input( subsample->in ) || 
		vips_check_coding_known( class->nickname, subsample->in ) )  
		return( -1 );

	/* Set demand hints. We want THINSTRIP, as we will be demanding a
	 * large area of input for each output line.
	 */
	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, subsample->in, NULL ) )
		return( -1 );

	/* Prepare output. Note: we round the output width down!
	 */
	conversion->out->Xsize = subsample->in->Xsize / subsample->xfac;
	conversion->out->Ysize = subsample->in->Ysize / subsample->yfac;
	conversion->out->Xres = subsample->in->Xres / subsample->xfac;
	conversion->out->Yres = subsample->in->Yres / subsample->yfac;
	if( conversion->out->Xsize <= 0 || 
		conversion->out->Ysize <= 0 ) {
		vips_error( class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

	/* Generate! If this is a very large shrink, then it's probably faster 
	 * to do it a pixel at a time. 
	 */
	if( subsample->point ||
		subsample->xfac > 10 ) 
		subsample_fn = vips_subsample_point_gen;
	else 
		subsample_fn = vips_subsample_line_gen;

	if( vips_image_generate( conversion->out, 
		vips_start_one, subsample_fn, vips_stop_one,
		subsample->in, subsample ) )
		return( -1 );

	return( 0 );
}

/* xy range we sanity check on ... just to stop crazy numbers from divide by 0 
 * etc. causing g_assert() failures later.
 */
#define RANGE (100000000)

static void
vips_subsample_class_init( VipsSubsampleClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "subsample";
	vobject_class->description = _( "subsample an image" );
	vobject_class->build = vips_subsample_build;

	/* We don't work well as sequential: we can easily skip the first few
	 * scanlines, and that confuses vips_sequential().
	 */

	VIPS_ARG_IMAGE( class, "input", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSubsample, in ) );

	VIPS_ARG_INT( class, "xfac", 2, 
		_( "Xfac" ), 
		_( "Horizontal subsample factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSubsample, xfac ),
		1, RANGE, 1 );

	VIPS_ARG_INT( class, "yfac", 3, 
		_( "Yfac" ), 
		_( "Vertical subsample factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSubsample, yfac ),
		1, RANGE, 1 );

	VIPS_ARG_BOOL( class, "point", 2, 
		_( "Point" ), 
		_( "Point sample" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSubsample, point ),
		FALSE );

}

static void
vips_subsample_init( VipsSubsample *subsample )
{
}

/**
 * vips_subsample:
 * @in: input image
 * @out: output image
 * @xfac: horizontal shrink factor
 * @yfac: vertical shrink factor
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @point: turn on point sample mode
 *
 * Subsample an image by an integer fraction. This is fast, nearest-neighbour
 * shrink.
 *
 * For small horizontal shrinks, this operation will fetch lines of pixels
 * from @in and then subsample that line. For large shrinks it will fetch
 * single pixels.
 *
 * If @point is set, @in will always be sampled in points. This can be faster 
 * if the previous operations in the pipeline are very slow.
 *
 * See also: vips_affine(), vips_shrink(), vips_zoom().
 * 
 * Returns: 0 on success, -1 on error.
 */
int
vips_subsample( VipsImage *in, VipsImage **out, int xfac, int yfac, ... )
{
	va_list ap;
	int result;

	va_start( ap, yfac );
	result = vips_call_split( "subsample", ap, in, out, xfac, yfac );
	va_end( ap );

	return( result );
}
