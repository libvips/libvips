/* 1st order mosaic functions
 *
 * 31/7/97 JC
 *	- done!
 * 12/9/97 JC
 *	- mods so global_balance() can work with 1st order mosaics
 * 27/12/99 JC
 * 	- now uses affine() stuff
 * 	- small tidies
 * 2/2/01 JC
 *	- added tunable max blend width
 * 23/3/01 JC
 *	- better mosaic1 calcs ... was a bit broken
 * 14/12/04
 *	- works for LABQ as well
 * 25/1/11
 * 	- gtk-doc
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
#include <vips/buf.h>
#include <vips/transform.h>

#include "pmosaicing.h"

/*
#define DEBUG
 */

/* define this to get old not-really-working joiner.
#define OLD
 */

/* Like im_similarity(), but return the transform we generated. 
 */
static int 
apply_similarity( VipsTransformation *trn, IMAGE *in, IMAGE *out, 
	double a, double b, double dx, double dy )
{
	trn->iarea.left = 0;
	trn->iarea.top = 0;
	trn->iarea.width = in->Xsize;
	trn->iarea.height = in->Ysize;
	trn->a = a;
	trn->b = -b;
	trn->c = b;
	trn->d = a;
	trn->idx = 0;
	trn->idy = 0;
	trn->odx = dx;
	trn->ody = dy;
	vips__transform_set_area( trn );
	if( vips__transform_calc_inverse( trn ) )
		return( -1 );

	if( vips__affine( in, out, trn ) )
		return( -1 );

	return( 0 );
}

/* A join function ... either left-right or top-bottom rotscalemerge.
 */
typedef int (*joinfn)( IMAGE *, IMAGE *, IMAGE *, 
	double, double, double, double, int );

/* similarity+lrmerge.
 */
int
im__lrmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	double a, double b, double dx, double dy, int mwidth )
{
	VipsTransformation trn;
	IMAGE *t1 = im_open_local( out, "im_lrmosaic1:1", "p" );
	VipsBuf buf;
	char text[1024];

	/* Scale, rotate and displace sec.
	 */
	if( !t1 || apply_similarity( &trn, sec, t1, a, b, dx, dy ) )
		return( -1 );

	/* And join to ref.
	 */
	if( im__lrmerge( ref, t1, out, 
		-trn.oarea.left, -trn.oarea.top, mwidth ) )
		return( -1 );

	/* Note parameters in history file ... for global balance to pick up
	 * later.
	 */
	im__add_mosaic_name( out );
	vips_buf_init_static( &buf, text, 1024 );
	vips_buf_appendf( &buf, "#LRROTSCALE <%s> <%s> <%s> <",
		im__get_mosaic_name( ref ), 
		im__get_mosaic_name( sec ), 
		im__get_mosaic_name( out ) );  
	vips_buf_appendg( &buf, a );
	vips_buf_appendf( &buf, "> <" );
	vips_buf_appendg( &buf, b );
	vips_buf_appendf( &buf, "> <" );
	vips_buf_appendg( &buf, dx );
	vips_buf_appendf( &buf, "> <" );
	vips_buf_appendg( &buf, dy );
	vips_buf_appendf( &buf, "> <%d>", mwidth );
	if( im_histlin( out, "%s", vips_buf_all( &buf ) ) )
		return( -1 );

	return( 0 );
}

/* similarity+tbmerge.
 */
int
im__tbmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	double a, double b, double dx, double dy, int mwidth )
{
	VipsTransformation trn;
	IMAGE *t1 = im_open_local( out, "im_lrmosaic1:2", "p" );
	VipsBuf buf;
	char text[1024];

	/* Scale, rotate and displace sec.
	 */
	if( !t1 || apply_similarity( &trn, sec, t1, a, b, dx, dy ) )
		return( -1 );

	/* And join to ref.
	 */
	if( im__tbmerge( ref, t1, out, 
		-trn.oarea.left, -trn.oarea.top, mwidth ) )
		return( -1 );

	/* Note parameters in history file ... for global balance to pick up
	 * later.
	 */
	im__add_mosaic_name( out );
	vips_buf_init_static( &buf, text, 1024 );
	vips_buf_appendf( &buf, "#TBROTSCALE <%s> <%s> <%s> <",
		im__get_mosaic_name( ref ), 
		im__get_mosaic_name( sec ), 
		im__get_mosaic_name( out ) );  
	vips_buf_appendg( &buf, a );
	vips_buf_appendf( &buf, "> <" );
	vips_buf_appendg( &buf, b );
	vips_buf_appendf( &buf, "> <" );
	vips_buf_appendg( &buf, dx );
	vips_buf_appendf( &buf, "> <" );
	vips_buf_appendg( &buf, dy );
	vips_buf_appendf( &buf, "> <%d>", mwidth );
	if( im_histlin( out, "%s", vips_buf_all( &buf ) ) )
		return( -1 );

	return( 0 );
}

/* Join two images, using a pair of tie-points as parameters.
 */
static int
rotjoin( IMAGE *ref, IMAGE *sec, IMAGE *out, joinfn jfn,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int mwidth )
{ 
	double a, b, dx, dy;

	/* Solve to get scale + rot + disp.
	 */
	if( im__coeff( xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2, 
		&a, &b, &dx, &dy ) )
		return( -1 );

	/* Scale, rotate and displace sec.
	 */
	if( jfn( ref, sec, out, a, b, dx, dy, mwidth ) )
		return( -1 );

	return( 0 );
}

/* Like rotjoin, but do a search to refine the tie-points.
 */
static int
rotjoin_search( IMAGE *ref, IMAGE *sec, IMAGE *out, joinfn jfn,
	int bandno,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth )
{ 
	VipsTransformation trn;
	double cor1, cor2;
	double a, b, dx, dy;
	double xs3, ys3;
	double xs4, ys4;
	int xs5, ys5;
	int xs6, ys6;
	double xs7, ys7;
	double xs8, ys8;

	/* Temps.
	 */
	IMAGE *t[3];

	if( im_open_local_array( out, t, 3, "rotjoin_search", "p" ) )
		return( -1 );

	/* Unpack LABQ to LABS for correlation.
	 */
	if( ref->Coding == IM_CODING_LABQ ) {
		if( im_LabQ2LabS( ref, t[0] ) )
			return( -1 );
	}
	else
		t[0] = ref;
	if( sec->Coding == IM_CODING_LABQ ) {
		if( im_LabQ2LabS( sec, t[1] ) )
			return( -1 );
	}
	else
		t[1] = sec;

	/* Solve to get scale + rot + disp.
	 */
	if( im__coeff( xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2, 
		&a, &b, &dx, &dy ) ||
		apply_similarity( &trn, t[1], t[2], a, b, dx, dy ) ) 
		return( -1 );

	/* Map points on sec to rotated image.
	 */
	vips__transform_forward_point( &trn, xs1, ys1, &xs3, &ys3 );
	vips__transform_forward_point( &trn, xs2, ys2, &xs4, &ys4 );

	/* Refine tie-points on rotated image. Remember the clip
	 * vips__transform_set_area() has set, and move the sec tie-points 
	 * accordingly.
	 */
	if( im_correl( t[0], t[2], xr1, yr1, 
		xs3 - trn.oarea.left, ys3 - trn.oarea.top,
		halfcorrelation, halfarea, &cor1, &xs5, &ys5 ) )
		return( -1 );
	if( im_correl( t[0], t[2], xr2, yr2, 
		xs4 - trn.oarea.left, ys4 - trn.oarea.top,
		halfcorrelation, halfarea, &cor2, &xs6, &ys6 ) )
		return( -1 );

#ifdef DEBUG
	printf( "rotjoin_search: nudged pair 1 from %d, %d to %d, %d\n",
		xs3 - trn.oarea.left, ys3 - trn.oarea.top,
		xs5, ys5 );
	printf( "rotjoin_search: nudged pair 2 from %d, %d to %d, %d\n",
		xs4 - trn.oarea.left, ys4 - trn.oarea.top,
		xs6, ys6 );
#endif /*DEBUG*/

	/* Put the sec tie-points back into output space.
	 */
	xs5 += trn.oarea.left;
	ys5 += trn.oarea.top;
	xs6 += trn.oarea.left;
	ys6 += trn.oarea.top;

	/* ... and now back to input space again.
	 */
	vips__transform_invert_point( &trn, xs5, ys5, &xs7, &ys7 );
	vips__transform_invert_point( &trn, xs6, ys6, &xs8, &ys8 );

	/* Recalc the transform using the refined points.
	 */
	if( im__coeff( xr1, yr1, xs7, ys7, xr2, yr2, xs8, ys8, 
		&a, &b, &dx, &dy ) )
		return( -1 );

	/* Scale and rotate final.
	 */
	if( jfn( ref, sec, out, a, b, dx, dy, mwidth ) )
		return( -1 );

	return( 0 );
}

#ifdef OLD
/* 1st order mosaic using im__find_lroverlap() ... does not work too well :(
 * Look at im__find_lroverlap() for problem?
 */
static int
old_lrmosaic1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth )
{ 
	VipsTransformation trn1, trn2;
	int dx0, dy0;
	double a, b, dx, dy;
	double a1, b1, dx1, dy1;
	double af, bf, dxf, dyf;
	int xpos, ypos;
	int xpos1, ypos1;

	/* Temps.
	 */
	IMAGE *t1 = im_open_local( out, "im_lrmosaic1:1", "p" );
	IMAGE *t2 = im_open_local( out, "im_lrmosaic1:2", "p" );
	IMAGE *dummy;

	if( !t1 || !t2 )
		return( -1 );

	/* Solve to get scale + rot + disp.
	 */
	if( im__coeff( xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2, 
		&a, &b, &dx, &dy ) ||
		apply_similarity( &trn1, sec, t1, a, b, dx, dy ) )
		return( -1 );

	/* Correct tie-points. dummy is just a placeholder used to ensure that
	 * memory used by the analysis phase is freed as soon as possible.
	 */
	if( !(dummy = im_open( "placeholder:1", "p" )) )
		return( -1 );
	if( im__find_lroverlap( ref, t1, dummy,
		bandno, 
		-trn1.area.left, -trn1.area.top, 0, 0,
		halfcorrelation, halfarea,
		&dx0, &dy0,
		&a1, &b1, &dx1, &dy1 ) ) {
		im_close( dummy );
		return( -1 );
	}
	im_close( dummy );

	/* Now combine the two transformations to get a corrected transform.
	 */
	af = a1 * a - b1 * b;
	bf = a1 * b + b1 * a;
	dxf = a1 * dx - b1 * dy + dx1;
	dyf = b1 * dx + a1 * dy + dy1;

	printf( "transform was: a = %g, b = %g, dx = %g, dy = %g\n",
		a, b, dx, dy );
	printf( "correction: a = %g, b = %g, dx = %g, dy = %g\n",
		a1, b1, dx1, dy1 );
	printf( "final: a = %g, b = %g, dx = %g, dy = %g\n",
		af, bf, dxf, dyf );

	/* Scale and rotate final.
	 */
	if( apply_similarity( &trn2, sec, t2, af, bf, dxf, dyf ) )
		return( -1 );

	printf( "disp: trn1 left = %d, top = %d\n", 
		trn1.area.left, trn1.area.top );
	printf( "disp: trn2 left = %d, top = %d\n", 
		trn2.area.left, trn2.area.top );

	/* And join to ref.
	 */
	if( im_lrmerge( ref, t2, out, 
		-trn2.area.left, -trn2.area.top, mwidth ) )
		return( -1 );

	return( 0 );
}
#endif /*OLD*/

typedef struct {
	VipsOperation parent_instance;

	VipsImage *ref;
	VipsImage *sec;
	VipsImage *out;
	VipsDirection direction;
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
	int mblend;
	int bandno;

} VipsMosaic1;

typedef VipsOperationClass VipsMosaic1Class;

G_DEFINE_TYPE( VipsMosaic1, vips_mosaic1, VIPS_TYPE_OPERATION );

static int
vips_mosaic1_build( VipsObject *object )
{
	VipsMosaic1 *mosaic1 = (VipsMosaic1 *) object;

	joinfn jfn;

	g_object_set( mosaic1, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_mosaic1_parent_class )->build( object ) )
		return( -1 );

	if( !mosaic1->interpolate )
		mosaic1->interpolate = vips_interpolate_new( "bilinear" );

	jfn = mosaic1->direction == VIPS_DIRECTION_HORIZONTAL ?
		im__lrmerge1 : im__tbmerge1;

	if( mosaic1->search ) {
		if( rotjoin_search( mosaic1->ref, mosaic1->sec, mosaic1->out, 
			jfn,
			mosaic1->bandno,
			mosaic1->xr1, mosaic1->yr1, mosaic1->xs1, mosaic1->ys1, 
			mosaic1->xr2, mosaic1->yr2, mosaic1->xs2, mosaic1->ys2,
			mosaic1->hwindow, mosaic1->harea, 
			0,
			mosaic1->mblend ) )
			return( -1 );
	}
	else {
		if( rotjoin( mosaic1->ref, mosaic1->sec, mosaic1->out, 
			jfn,
			mosaic1->xr1, mosaic1->yr1, mosaic1->xs1, mosaic1->ys1, 
			mosaic1->xr2, mosaic1->yr2, mosaic1->xs2, mosaic1->ys2,
			mosaic1->mblend ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_mosaic1_class_init( VipsMosaic1Class *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "mosaic1";
	object_class->description = _( "first-order mosaic of two images" );
	object_class->build = vips_mosaic1_build;

	VIPS_ARG_IMAGE( class, "ref", 1, 
		_( "Reference" ), 
		_( "Reference image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMosaic1, ref ) );

	VIPS_ARG_IMAGE( class, "sec", 2, 
		_( "Secondary" ), 
		_( "Secondary image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMosaic1, sec ) );

	VIPS_ARG_IMAGE( class, "out", 3, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMosaic1, out ) );

	VIPS_ARG_ENUM( class, "direction", 4, 
		_( "Direction" ), 
		_( "Horizontal or vertcial mosaic" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMosaic1, direction ), 
		VIPS_TYPE_DIRECTION, VIPS_DIRECTION_HORIZONTAL ); 

	VIPS_ARG_INT( class, "xr1", 5, 
		_( "xr1" ), 
		_( "Position of first reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, xr1 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "yr1", 6, 
		_( "yr1" ), 
		_( "Position of first reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, yr1 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "xs1", 7, 
		_( "xs1" ), 
		_( "Position of first secondary tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, xs1 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "ys1", 8, 
		_( "ys1" ), 
		_( "Position of first secondary tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, ys1 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "xr2", 9, 
		_( "xr2" ), 
		_( "Position of second reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, xr2 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "yr2", 10, 
		_( "yr2" ), 
		_( "Position of second reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, yr2 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "xs2", 11, 
		_( "xs2" ), 
		_( "Position of second secondary tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, xs2 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "ys2", 12, 
		_( "ys2" ), 
		_( "Position of second secondary tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, ys2 ),
		-1000000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "hwindow", 13, 
		_( "hwindow" ), 
		_( "Half window size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, hwindow ),
		0, 1000000000, 1 );

	VIPS_ARG_INT( class, "harea", 14, 
		_( "harea" ), 
		_( "Half area size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, harea ),
		0, 1000000000, 1 );

	VIPS_ARG_BOOL( class, "search", 15, 
		_( "search" ), 
		_( "Search to improve tie-points" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, search ),
		FALSE ); 

	VIPS_ARG_INTERPOLATE( class, "interpolate", 16, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsMosaic1, interpolate ) );

	VIPS_ARG_INT( class, "mblend", 17, 
		_( "Max blend" ), 
		_( "Maximum blend size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, mblend ),
		0, 10000, 10 );

	VIPS_ARG_INT( class, "bandno", 18, 
		_( "Search band" ), 
		_( "Band to search for features on" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic1, bandno ),
		0, 10000, 0 );

}

static void
vips_mosaic1_init( VipsMosaic1 *mosaic1 )
{
	mosaic1->hwindow = 5;
	mosaic1->harea = 15;
	mosaic1->mblend = 10;
}

/**
 * vips_mosaic1:
 * @ref: reference image
 * @sec: secondary image
 * @out: output image
 * @direction: horizontal or vertical join
 * @xr1: first reference tie-point
 * @yr1: first reference tie-point
 * @xs1: first secondary tie-point
 * @ys1: first secondary tie-point
 * @xr2: second reference tie-point
 * @yr2: second reference tie-point
 * @xs2: second secondary tie-point
 * @ys2: second secondary tie-point
 * @...: %NULL-terminated list of optional named arguments
 * 
 * Optional arguments:
 *
 * @search: search to improve tie-points
 * @hwindow: half window size
 * @harea: half search size 
 * @interpolate: interpolate pixels with this
 * @mblend: maximum blend size 
 * @bandno: band to search for features
 *
 * This operation joins two images top-bottom (with @sec on the right) 
 * or left-right (with @sec at the bottom)
 * given an approximate pair of tie-points. @sec is scaled and rotated as
 * necessary before the join.
 *
 * Before performing the transformation, the tie-points are improved by 
 * searching band @bandno in an area of @sec of size @hsearchsize for a
 * match of size @hwindowsize to @ref. 
 *
 * If @search is %TRUE, before performing the transformation, the tie-points 
 * are improved by searching an area of @sec of size @harea for a
 * mosaic1 of size @hwindow to @ref. 
 *
 * @mblend limits  the  maximum size of the
 * blend area.  A value of "-1" means "unlimited". The two images are blended 
 * with a raised cosine. 
 *
 * Pixels with all bands equal to zero are "transparent", that
 * is, zero pixels in the overlap area do not  contribute  to  the  merge.
 * This makes it possible to join non-rectangular images.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="libvips-arithmetic">arithmetic</link>).
 *
 * See also: vips_merge(), vips_insert(), vips_globalbalance().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mosaic1( VipsImage *ref, VipsImage *sec, VipsImage **out, 
	VipsDirection direction, 
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2, ... )
{
	va_list ap;
	int result;

	va_start( ap, ys2 );
	result = vips_call_split( "mosaic1", ap, ref, sec, out, direction,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2 );
	va_end( ap );

	return( result );
}
