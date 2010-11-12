/* im_insert
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on : 
 * 31/8/93 JC
 *	- ANSIfied
 *	- Nicos' reformatting undone. Grr!
 * 22/12/94
 *	- modernised
 *	- now does IM_CODING_LABQ too
 * 22/6/95 JC
 *	- partialized
 * 10/2/02 JC
 *	- adapted for im_prepare_to() stuff
 * 14/4/04
 *	- sets Xoffset / Yoffset
 * 3/7/06
 * 	- add sanity range checks
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 30/1/10
 * 	- cleanups
 * 	- formatalike/bandalike
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* The common part of most binary conversion
 * operators. We:
 *
 * - check in and out
 * - cast in1 and in2 up to a common format
 * - equalise bands 
 * - make an input array
 * - run the supplied area operation passing one of the up-banded,
 *   up-casted and up-sized inputs as the first param
 */
static IMAGE **
im__insert_base( const char *domain, 
	IMAGE *in1, IMAGE *in2, IMAGE *out ) 
{
	IMAGE *t[4];
	IMAGE **vec;

	if( im_piocheck( in1, out ) || 
		im_pincheck( in2 ) ||
		im_check_bands_1orn( domain, in1, in2 ) ||
		im_check_coding_known( domain, in1 ) ||
		im_check_coding_same( domain, in1, in2 ) )
		return( NULL );

	/* Cast our input images up to a common format and bands.
	 */
	if( im_open_local_array( out, t, 4, domain, "p" ) ||
		im__formatalike( in1, in2, t[0], t[1] ) ||
		im__bandalike( domain, t[0], t[1], t[2], t[3] ) ||
		!(vec = im_allocate_input_array( out, t[2], t[3], NULL )) )
		return( NULL );

	/* Generate the output.
	 */
	if( im_cp_descv( out, vec[0], vec[1], NULL ) ||
		im_demand_hint_array( out, IM_SMALLTILE, vec ) )
		return( NULL );

	return( vec );
}

/* Hold our state in this.
 */
typedef struct {
	/* Args.
	 */
	IMAGE *main;		/* Main image */
	IMAGE *sub;		/* Sub image */
	IMAGE *out;		/* Output image */
	int x, y;		/* Position of sub wrt. main */

	/* Geometry.
	 */
	Rect rout;		/* Output space */
	Rect rmain;		/* Position of main in output */
	Rect rsub;		/* Position of sub in output */
} InsertState;

/* Trivial case: we just need pels from one of the inputs.
 */
static int
just_one( REGION *or, REGION *ir, int x, int y )
{
	Rect need;

	/* Find the part of pos we need.
	 */
	need = or->valid;
	need.left -= x;
	need.top -= y;
	if( im_prepare( ir, &need ) )
		return( -1 );

	/* Attach our output to it.
	 */
	if( im_region_region( or, ir, &or->valid, need.left, need.top ) )
		return( -1 );

	return( 0 );
}

/* Paste in parts of ir that fall within or --- ir is an input REGION for an 
 * image positioned at pos within or.
 */
static int
paste_region( REGION *or, REGION *ir, Rect *pos )
{
	Rect ovl;

	/* Does any of the sub-image appear in the area we have been asked
	 * to make?
	 */
	im_rect_intersectrect( &or->valid, pos, &ovl );
	if( !im_rect_isempty( &ovl ) ) {
		/* Find the part of in we need.
		 */
		ovl.left -= pos->left;
		ovl.top -= pos->top;

		/* Paint this area of pixels into or.
		 */
		if( im_prepare_to( ir, or, &ovl, 
			ovl.left + pos->left, ovl.top + pos->top ) )
			return( -1 );
	}

	return( 0 );
}

/* Insert generate function.
 */
static int
insert_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION **ir = (REGION **) seq;
	InsertState *ins = (InsertState *) b;
	Rect ovl;

	/* Does the rect we have been asked for fall entirely inside the
	 * sub-image?
	 */
	if( im_rect_includesrect( &ins->rsub, &or->valid ) ) 
		return( just_one( or, ir[1], 
			ins->rsub.left, ins->rsub.top ) );
	
	/* Does it fall entirely inside the main, and not at all inside the
	 * sub?
	 */
	im_rect_intersectrect( &or->valid, &ins->rsub, &ovl );
	if( im_rect_includesrect( &ins->rmain, &or->valid ) &&
		im_rect_isempty( &ovl ) ) 
		return( just_one( or, ir[0], 
			ins->rmain.left, ins->rmain.top ) );

	/* Output requires both (or neither) input. If it is not entirely 
	 * inside both the main and the sub, then there is going to be some
	 * black. 
	 */
	if( !(im_rect_includesrect( &ins->rsub, &or->valid ) &&
		im_rect_includesrect( &ins->rmain, &or->valid )) )
		/* Could be clever --- but just black the whole thing for
		 * simplicity.
		 */
		im_region_black( or );

	/* Paste from main.
	 */
	if( paste_region( or, ir[0], &ins->rmain ) )
		return( -1 );

	/* Paste from sub.
	 */
	if( paste_region( or, ir[1], &ins->rsub ) )
		return( -1 );

	return( 0 );
}

/* xy range we sanity check on ... just to stop crazy numbers from 1/0 etc.
 * causing assert() failures later.
 */
#define RANGE (10000000)

/**
 * im_insert:
 * @main: big image
 * @sub: small image
 * @out: output image
 * @x: left position of @sub
 * @y: top position of @sub
 *
 * Insert one image into another. @sub is inserted into image @main at
 * position @x, @y relative to the top LH corner of @main. @out is made large
 * enough to hold both @main and @sub. Any areas of @out not coming from
 * either @main or @sub are set to black (binary 0). If @sub overlaps @main,
 * @sub will appear on top of @main. 
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_insert_noexpand(), im_lrjoin().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_insert( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y )
{
	InsertState *ins;
	IMAGE **vec;

	/* Check args.
	 */
	if( x > RANGE || x < -RANGE || y > RANGE || y < -RANGE ) {
		im_error( "im_insert", "%s", _( "xy out of range" ) );
		return( -1 ); 
	}
	if( !(ins = IM_NEW( out, InsertState )) ||
		!(vec = im__insert_base( "im_insert", main, sub, out )) )
		return( -1 );

	/* Save args.
	 */
	ins->main = vec[0];
	ins->sub = vec[1];
	ins->out = out;
	ins->x = x;
	ins->y = y;

	/* Calculate geometry. First, position rmain and rsub with (0,0) at
	 * top LH corner of main.
	 */
	ins->rmain.left = 0;
	ins->rmain.top = 0;
	ins->rmain.width = vec[0]->Xsize;
	ins->rmain.height = vec[0]->Ysize;
	ins->rsub.left = x;
	ins->rsub.top = y;
	ins->rsub.width = vec[1]->Xsize;
	ins->rsub.height = vec[1]->Ysize;

	/* Now: output is bounding box of these two.
	 */
	im_rect_unionrect( &ins->rmain, &ins->rsub, &ins->rout );

	/* Translate origin to top LH corner of rout.
	 */
	ins->rmain.left -= ins->rout.left;
	ins->rmain.top -= ins->rout.top;
	ins->rsub.left -= ins->rout.left;
	ins->rsub.top -= ins->rout.top;
	ins->rout.left = 0;
	ins->rout.top = 0;

	/* Set up the output header.  
	 */
	out->Xsize = ins->rout.width;
	out->Ysize = ins->rout.height;

	/* Make output image.
	 */
	if( im_generate( out, 
		im_start_many, insert_gen, im_stop_many, vec, ins ) )
		return( -1 );

	out->Xoffset = ins->rmain.left;
	out->Yoffset = ins->rmain.top;

	return( 0 );
}

/**
 * im_insert_noexpand:
 * @main: big image
 * @sub: small image
 * @out: output image
 * @x: left position of @sub
 * @y: top position of @sub
 *
 * Insert one image into another. @sub is inserted into image @main at
 * position @x, @y relative to the top LH corner of @main. @out is the same
 * size as @main. @sub is clipped against the edges of @main. 
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_insert_noexpand(), im_lrjoin(), im_draw_image().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_insert_noexpand( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y )
{
	InsertState *ins;
	IMAGE **vec;

	/* Check args.
	 */
	if( x > RANGE || x < -RANGE || y > RANGE || y < -RANGE ) {
		im_error( "im_insert", "%s", _( "xy out of range" ) );
		return( -1 ); 
	}
	if( !(ins = IM_NEW( out, InsertState )) ||
		!(vec = im__insert_base( "im_insert", main, sub, out )) )
		return( -1 );

	/* Save args.
	 */
	ins->main = vec[0];
	ins->sub = vec[1];
	ins->out = out;
	ins->x = x;
	ins->y = y;

	/* Calculate geometry. 
	 */
	ins->rmain.left = 0;
	ins->rmain.top = 0;
	ins->rmain.width = vec[0]->Xsize;
	ins->rmain.height = vec[0]->Ysize;
	ins->rsub.left = x;
	ins->rsub.top = y;
	ins->rsub.width = vec[1]->Xsize;
	ins->rsub.height = vec[1]->Ysize;
	ins->rout = ins->rmain;

	/* Set up the output header.  
	 */
	out->Xsize = ins->rout.width;
	out->Ysize = ins->rout.height;

	/* Make output image.
	 */
	if( im_generate( out, 
		im_start_many, insert_gen, im_stop_many, vec, ins ) )
		return( -1 );

	return( 0 );
}

/**
 * im_insertset:
 * @main: big image
 * @sub: small image
 * @out: output image
 * @n: number of positions
 * @x: left positions of @sub
 * @y: top positions of @sub
 *
 * Insert @sub repeatedly into @main at the positions listed in the arrays @x,
 * @y of length @n. @out is the same
 * size as @main. @sub is clipped against the edges of @main. 
 *
 * This operation is fast for large @n, but will use a memory buffer the size
 * of @out. It's useful for things like making scatter plots.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_insert(), im_lrjoin().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_insertset( IMAGE *main, IMAGE *sub, IMAGE *out, int n, int *x, int *y )
{
	IMAGE **vec;
	IMAGE *t;
	int i;

	if( !(vec = im__insert_base( "im_insert", main, sub, out )) )
		return( -1 );

	/* Copy to a memory image, zap that, then copy to out.
	 */
	if( !(t = im_open_local( out, "im_insertset", "t" )) ||
		im_copy( vec[0], t ) )
		return( -1 );

	for( i = 0; i < n; i++ ) 
		if( im_insertplace( t, vec[1], x[i], y[i] ) )
			return( -1 );

	if( im_copy( t, out ) )
		return( -1 );

	return( 0 );
}
