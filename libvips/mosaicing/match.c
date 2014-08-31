/* Match images.
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

#include <vips/vips.h>

#include "pmosaicing.h"

/* Given a pair of points, return scale, angle, dx, dy to resample the 2nd
 * image with.
 */
int 
im__coeff( int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2, 
	double *a, double *b, double *dx, double *dy )
{	
	DOUBLEMASK *in, *out;

	if( !(in = im_create_dmask( "in", 4, 4 )) ) 
		return( -1 );

	in->coeff[0] = (double)xs1;
	in->coeff[1] = (double)-ys1;
	in->coeff[2] = 1.0;
	in->coeff[3] = 0.0;
	in->coeff[4] = (double)ys1;
	in->coeff[5] = (double)xs1;
	in->coeff[6] = 0.0;
	in->coeff[7] = 1.0;
	in->coeff[8] = (double)xs2;
	in->coeff[9] = (double)-ys2;
	in->coeff[10] = 1.0;
	in->coeff[11] = 0.0;
	in->coeff[12] = (double)ys2;
	in->coeff[13] = (double)xs2;
	in->coeff[14] = 0.0;
	in->coeff[15] = 1.0;

	if( !(out = im_matinv( in, "out" )) ) {
		im_free_dmask( in );
		return( -1 );
	}

	*a = out->coeff[0]*xr1 + out->coeff[1]*yr1 + 
		out->coeff[2]*xr2 + out->coeff[3]*yr2;
	*b = out->coeff[4]*xr1 + out->coeff[5]*yr1 + 
		out->coeff[6]*xr2 + out->coeff[7]*yr2;
	*dx= out->coeff[8]*xr1 + out->coeff[9]*yr1 + 	
		out->coeff[10]*xr2 + out->coeff[11]*yr2;
	*dy= out->coeff[12]*xr1 + out->coeff[13]*yr1 + 
		out->coeff[14]*xr2 + out->coeff[15]*yr2;

	im_free_dmask( in );
	im_free_dmask( out );

	return( 0 );
}

typedef struct {
	VipsOperation parent_instance;

	VipsImage *ref;
	VipsImage *sec;
	VipsImage *out;
	int xr1;
	int yr1;
	int xs1;
	int ys1;
	int xr2;
	int yr2;
	int xs2;
	int ys2;
	int hwindow;
	int harea;
	gboolean search;
	VipsInterpolate *interpolate;

} VipsMatch;

typedef VipsOperationClass VipsMatchClass;

G_DEFINE_TYPE( VipsMatch, vips_match, VIPS_TYPE_OPERATION );

static int
vips_match_build( VipsObject *object )
{
	VipsMatch *match = (VipsMatch *) object;

	double a, b, dx, dy;
	VipsArrayInt *oarea;
	VipsImage *x;

	g_object_set( match, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_match_parent_class )->build( object ) )
		return( -1 );

	if( !match->interpolate )
		match->interpolate = vips_interpolate_new( "bilinear" );

	if( match->search ) {
		int xs, ys;
		double cor;

		if( im_correl( match->ref, match->sec, 
			match->xr1, match->yr1, match->xs1, match->ys1,
			match->hwindow, match->harea, 
			&cor, &xs, &ys ) )
			return( -1 ); 
		match->xs1 = xs;
		match->ys1 = ys;

		if( im_correl( match->ref, match->sec, 
			match->xr2, match->yr2, match->xs2, match->ys2,
			match->hwindow, match->harea, 
			&cor, &xs, &ys ) )
			return( -1 ); 

		match->xs2 = xs;
		match->ys2 = ys;
	}

	/* Solve to get scale + rot + disp to obtain match.
	 */
	if( im__coeff( match->xr1, match->yr1, match->xs1, match->ys1, 
		match->xr2, match->yr2, match->xs2, match->ys2, 
		&a, &b, &dx, &dy ) )
		return( -1 );

	/* Output area of ref image.
	 */
	oarea = vips_array_int_newv( 4, 
		0, 0, match->ref->Xsize, match->ref->Ysize ); 

	if( vips_affine( match->sec, &x,
		a, -b, b, a, 
		"interpolate", match->interpolate, 
		"odx", dx, 
		"ody", dy, 
		"oarea", oarea, 
		NULL ) ) {
		vips_area_unref( VIPS_AREA( oarea ) );
		return( -1 );
	}
	vips_area_unref( VIPS_AREA( oarea ) );

	if( vips_image_write( x, match->out ) ) {
		g_object_unref( x ); 
		return( -1 ); 
	}
	g_object_unref( x ); 

	return( 0 );
}

static void
vips_match_class_init( VipsMatchClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "match";
	object_class->description = _( "first-order match of two images" );
	object_class->build = vips_match_build;

	VIPS_ARG_IMAGE( class, "ref", 1, 
		_( "Reference" ), 
		_( "Reference image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMatch, ref ) );

	VIPS_ARG_IMAGE( class, "sec", 2, 
		_( "Secondary" ), 
		_( "Secondary image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMatch, sec ) );

	VIPS_ARG_IMAGE( class, "out", 3, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMatch, out ) );

	VIPS_ARG_INT( class, "xr1", 5, 
		_( "xr1" ), 
		_( "Position of first reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatch, xr1 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "yr1", 6, 
		_( "yr1" ), 
		_( "Position of first reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatch, yr1 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "xs1", 7, 
		_( "xs1" ), 
		_( "Position of first secondary tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatch, xs1 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "ys1", 8, 
		_( "ys1" ), 
		_( "Position of first secondary tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatch, ys1 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "xr2", 9, 
		_( "xr2" ), 
		_( "Position of second reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatch, xr2 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "yr2", 10, 
		_( "yr2" ), 
		_( "Position of second reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatch, yr2 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "xs2", 11, 
		_( "xs2" ), 
		_( "Position of second secondary tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatch, xs2 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "ys2", 12, 
		_( "ys2" ), 
		_( "Position of second secondary tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatch, ys2 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "hwindow", 13, 
		_( "hwindow" ), 
		_( "Half window size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMatch, hwindow ),
		0, 1000000000, 1 );

	VIPS_ARG_INT( class, "harea", 14, 
		_( "harea" ), 
		_( "Half area size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMatch, harea ),
		0, 1000000000, 1 );

	VIPS_ARG_BOOL( class, "search", 15, 
		_( "search" ), 
		_( "Search to improve tie-points" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMatch, search ),
		FALSE ); 

	VIPS_ARG_INTERPOLATE( class, "interpolate", 16, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsMatch, interpolate ) );

}

static void
vips_match_init( VipsMatch *match )
{
	match->hwindow = 5;
	match->harea = 15;
	match->search = FALSE;
}

/**
 * vips_match:
 * @ref: reference image
 * @sec: secondary image
 * @out: output image
 * @xr1: first reference tie-point
 * @yr1: first reference tie-point
 * @xs1: first secondary tie-point
 * @ys1: first secondary tie-point
 * @xr2: second reference tie-point
 * @yr2: second reference tie-point
 * @xs2: second secondary tie-point
 * @ys2: second secondary tie-point
 * 
 * Optional arguments:
 *
 * @search: search to improve tie-points
 * @hwindow: half window size
 * @harea: half search size 
 * @interpolate: interpolate pixels with this
 *
 * Scale, rotate and translate @sec so that the tie-points line up.
 *
 * If @search is %TRUE, before performing the transformation, the tie-points 
 * are improved by searching an area of @sec of size @harea for a
 * match of size @hwindow to @ref. 
 *
 * This function will only work well for small rotates and scales.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_match( VipsImage *ref, VipsImage *sec, VipsImage **out, 
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2, ... )
{
	va_list ap;
	int result;

	va_start( ap, ys2 );
	result = vips_call_split( "match", ap, ref, sec, out, 
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2 );
	va_end( ap );

	return( result );
}
