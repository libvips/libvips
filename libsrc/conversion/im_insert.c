/* @(#) Insert one image into another. ins is inserted into image in at
 * @(#) position x, y relative to the top LH corner of in. out is made large
 * @(#) enough to hold both in and ins. Any areas of out not coming from
 * @(#) either in or ins are set to black (binary 0). If ins overlaps in, ins
 * @(#) will appear on top of in. Both images must have the same number of 
 * @(#) bands and the same BandFmt.
 * @(#)
 * @(#) im_insert_noepand() always outputs an image the same size as in.
 * @(#)
 * @(#) Usage:
 * @(#)
 * @(#) int im_insert(in, ins, out, x, y )
 * @(#) IMAGE *in, *ins, *out;
 * @(#) int x, y;
 * @(#)
 * @(#) int im_insert_noexpand(in, ins, out, x, y )
 * @(#) IMAGE *in, *ins, *out;
 * @(#) int x, y;
 * @(#)
 * @(#) Returns 0 on success and -1 on error.
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

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

/* Black out a region.
 */
static void
black_region( REGION *reg )
{
	PEL *q = (PEL *) IM_REGION_ADDR( reg, reg->valid.left, reg->valid.top );
	int wd = IM_REGION_SIZEOF_LINE( reg );
	int ls = IM_REGION_LSKIP( reg );
	int y;

	for( y = 0; y < reg->valid.height; y++, q += ls )
		memset( (char *) q, 0, wd );
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
insert_gen( REGION *or, REGION **ir, IMAGE **vec, InsertState *ins )
{
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
		black_region( or );

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
 * causing assert() failuresd later.
 */
#define RANGE (10000000)

/* Do an insert.  
 */
int 
im_insert( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y )
{
	InsertState *ins = IM_NEW( out, InsertState );
	IMAGE **vec;

	/* Check args.
	 */
	if( !ins || im_piocheck( main, out ) || im_pincheck( sub ) )
		return( -1 );
	if( main->BandFmt != sub->BandFmt || main->Bands != sub->Bands ||
		main->Coding != sub->Coding ) {
		im_error( "im_insert", _( "inputs differ in format" ) ); 
		return( -1 ); 
	}
	if( main->Coding != IM_CODING_NONE && main->Coding != IM_CODING_LABQ ) {
		im_error( "im_insert", 
			_( "input should be uncoded or IM_CODING_LABQ" ) ); 
		return( -1 ); 
	}
	if( x > RANGE || x < -RANGE || y > RANGE || y < -RANGE ) {
		im_error( "im_insert", _( "xy out of range" ) );
		return( -1 ); 
	}

	/* Save args.
	 */
	ins->main = main;
	ins->sub = sub;
	ins->out = out;
	ins->x = x;
	ins->y = y;

	/* Calculate geometry. First, position rmain and rsub with (0,0) at
	 * top LH corner of main.
	 */
	ins->rmain.left = 0;
	ins->rmain.top = 0;
	ins->rmain.width = main->Xsize;
	ins->rmain.height = main->Ysize;
	ins->rsub.left = x;
	ins->rsub.top = y;
	ins->rsub.width = sub->Xsize;
	ins->rsub.height = sub->Ysize;

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
	if( im_cp_descv( out, main, sub, NULL ) ) 
		return( -1 );
	out->Xsize = ins->rout.width;
	out->Ysize = ins->rout.height;

	/* Set demand hints.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, main, sub, NULL ) )
		 return( -1 );

	/* Make input array. 
	 */
	if( !(vec = im_allocate_input_array( out, main, sub, NULL )) )
		return( -1 );

	/* Make output image.
	 */
	if( im_generate( out, 
		im_start_many, insert_gen, im_stop_many, vec, ins ) )
		return( -1 );

	out->Xoffset = ins->rmain.left;
	out->Yoffset = ins->rmain.top;

	return( 0 );
}

/* As above, but don't expand to hold all of sub.
 */
int 
im_insert_noexpand( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y )
{
	InsertState *ins = IM_NEW( out, InsertState );
	IMAGE **vec;

	/* Check args.
	 */
	if( !ins || im_piocheck( main, out ) || im_pincheck( sub ) )
		return( -1 );
	if( main->BandFmt != sub->BandFmt || main->Bands != sub->Bands ||
		main->Coding != sub->Coding ) {
		im_error( "im_insert_noexpand", 
			_( "inputs differ in format" ) ); 
		return( -1 ); 
	}
	if( main->Coding != IM_CODING_NONE && main->Coding != IM_CODING_LABQ ) {
		im_error( "im_insert_noexpand", 
			_( "input should be uncoded or IM_CODING_LABQ" ) ); 
		return( -1 ); 
	}
	if( x > RANGE || x < -RANGE || y > RANGE || y < -RANGE ) {
		im_error( "im_insert", _( "xy out of range" ) );
		return( -1 ); 
	}

	/* Save args.
	 */
	ins->main = main;
	ins->sub = sub;
	ins->out = out;
	ins->x = x;
	ins->y = y;

	/* Calculate geometry. 
	 */
	ins->rmain.left = 0;
	ins->rmain.top = 0;
	ins->rmain.width = main->Xsize;
	ins->rmain.height = main->Ysize;
	ins->rsub.left = x;
	ins->rsub.top = y;
	ins->rsub.width = sub->Xsize;
	ins->rsub.height = sub->Ysize;
	ins->rout = ins->rmain;

	/* Set up the output header.  
	 */
	if( im_cp_descv( out, main, sub, NULL ) ) 
		return( -1 );
	out->Xsize = ins->rout.width;
	out->Ysize = ins->rout.height;

	/* Set demand hints.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, main, sub, NULL ) )
		 return( -1 );

	/* Make input array. 
	 */
	if( !(vec = im_allocate_input_array( out, main, sub, NULL )) )
		return( -1 );

	/* Make output image.
	 */
	if( im_generate( out, 
		im_start_many, insert_gen, im_stop_many, vec, ins ) )
		return( -1 );

	return( 0 );
}
