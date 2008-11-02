/* 1st order mosaic functions
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/buf.h>

#include "mosaic.h"
#include "merge.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/*
#define DEBUG
 */

/* define this to get old not-really-working joiner.
#define OLD
 */

/* Like im_similarity(), but return the transform we generated. 
 */
static int 
apply_similarity( Transformation *trn, IMAGE *in, IMAGE *out, 
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
	trn->dx = dx;
	trn->dy = dy;
	im__transform_set_area( trn );
	if( im__transform_calc_inverse( trn ) )
		return( -1 );

	if( im__affine( in, out, trn ) )
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
	Transformation trn;
	IMAGE *t1 = im_open_local( out, "im_lrmosaic1:1", "p" );
	im_buf_t buf;
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
	im_buf_init_static( &buf, text, 1024 );
	im_buf_appendf( &buf, "#LRROTSCALE <%s> <%s> <%s> <",
		ref->filename, sec->filename, out->filename ); 
	im_buf_appendg( &buf, a );
	im_buf_appendf( &buf, "> <" );
	im_buf_appendg( &buf, b );
	im_buf_appendf( &buf, "> <" );
	im_buf_appendg( &buf, dx );
	im_buf_appendf( &buf, "> <" );
	im_buf_appendg( &buf, dy );
	im_buf_appendf( &buf, "> <%d>", mwidth );
	if( im_histlin( out, "%s", im_buf_all( &buf ) ) )
		return( -1 );

	return( 0 );
}

/* similarity+tbmerge.
 */
int
im__tbmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	double a, double b, double dx, double dy, int mwidth )
{
	Transformation trn;
	IMAGE *t1 = im_open_local( out, "im_lrmosaic1:2", "p" );
	im_buf_t buf;
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
	im_buf_init_static( &buf, text, 1024 );
	im_buf_appendf( &buf, "#TBROTSCALE <%s> <%s> <%s> <",
		ref->filename, sec->filename, out->filename ); 
	im_buf_appendg( &buf, a );
	im_buf_appendf( &buf, "> <" );
	im_buf_appendg( &buf, b );
	im_buf_appendf( &buf, "> <" );
	im_buf_appendg( &buf, dx );
	im_buf_appendf( &buf, "> <" );
	im_buf_appendg( &buf, dy );
	im_buf_appendf( &buf, "> <%d>", mwidth );
	if( im_histlin( out, "%s", im_buf_all( &buf ) ) )
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

/* 1st order left-right merge.
 */
int
im_lrmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int mwidth )
{
	return( rotjoin( ref, sec, out, im__lrmerge1,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2, mwidth ) );
}

/* 1st order top-bottom merge.
 */
int
im_tbmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int mwidth )
{ 
	return( rotjoin( ref, sec, out, im__tbmerge1,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2, mwidth ) );
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
	Transformation trn;
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
	im__transform_forward( &trn, xs1, ys1, &xs3, &ys3 );
	im__transform_forward( &trn, xs2, ys2, &xs4, &ys4 );

	/* Refine tie-points on rotated image. Remember the clip
	 * im__transform_set_area() has set, and move the sec tie-points 
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
	im__transform_inverse( &trn, xs5, ys5, &xs7, &ys7 );
	im__transform_inverse( &trn, xs6, ys6, &xs8, &ys8 );

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

/* 1st order lr mosaic.
 */
int
im_lrmosaic1( IMAGE *ref, IMAGE *sec, IMAGE *out, 
	int bandno,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth )
{ 
	return( rotjoin_search( ref, sec, out, im__lrmerge1,
		bandno,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2,
		halfcorrelation, halfarea, balancetype,
		mwidth ) );
}

/* 1st order tb mosaic.
 */
int
im_tbmosaic1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth )
{ 
	return( rotjoin_search( ref, sec, out, im__tbmerge1,
		bandno,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2,
		halfcorrelation, halfarea, balancetype, mwidth ) );
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
	Transformation trn1, trn2;
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
