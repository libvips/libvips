/* @(#) im_complass: Optimised convolution for line detection
 * @(#) Uses the entered mask and 7 rotated versions of it (each by 45 degrees)
 * @(#)
 * @(#) Usage 
 * @(#) int im_compass( in, out, m )
 * @(#) IMAGE *in, *out;
 * @(#) INTMASK *m;
 * @(#)
 * @(#) Returns 0 on sucess and -1 on error
 * @(#)
 * @(#) Returns an int pointer to valid offsets for rotating a square mask 
 * @(#) of odd size by 45 degrees.
 * @(#)
 * @(#) Usage 
 * @(#) int *im_offsets45( size )
 * @(#) int size;
 * @(#)
 * @(#) Returns an int pointer to valid offsets on sucess and -1 on error
 * @(#)
 * 
 * Author: N. Dessipris (Copyright, N. Dessipris 1991)
 * Written on: 08/05/1991
 * Modified on: 
 * 11/3/01 JC
 *	- rewritten, calling im_conv() and im_maxvalue()
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
#include <limits.h>
#include <assert.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_compass( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *filtered[8];
	IMAGE *absed[8];
	int i;

	if( im_open_local_array( out, filtered, 8, "im_compass:1", "p" ) ||
		im_open_local_array( out, absed, 8, "im_compass:2", "p" ) )
		return( -1 );

	for( i = 0; i < 8; i++ ) {
		if( im_conv( in, filtered[i], mask ) ||
		    !(mask = (INTMASK *) im_local( out, 
			(im_construct_fn) im_rotate_imask45,
			(im_callback_fn) im_free_imask,
			mask, mask->filename, NULL )) )
			return( -1 );
	}

	for( i = 0; i < 8; i++ ) 
		if( im_abs( filtered[i], absed[i] ) )
			return( -1 );

	return( im_maxvalue( absed, out, 8 ) );
}

int 
im_lindetect( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *filtered[4];
	IMAGE *absed[4];
	int i;

	if( im_open_local_array( out, filtered, 4, "im_lindetect:1", "p" ) ||
		im_open_local_array( out, absed, 4, "im_lindetect:2", "p" ) )
		return( -1 );

	for( i = 0; i < 4; i++ ) {
		if( im_conv( in, filtered[i], mask ) ||
		    !(mask = (INTMASK *) im_local( out, 
			(im_construct_fn) im_rotate_imask45,
			(im_callback_fn) im_free_imask,
			mask, mask->filename, NULL )) )
			return( -1 );
	}

	for( i = 0; i < 4; i++ ) 
		if( im_abs( filtered[i], absed[i] ) )
			return( -1 );

	return( im_maxvalue( absed, out, 4 ) );
}

#define GTEMPS (4)

int
im_gradient( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *t[GTEMPS];
	INTMASK *rmask;

	if( im_open_local_array( out, t, GTEMPS, "im_gradient", "p" ) )
		return( -1 );

	if( !(rmask = (INTMASK *) im_local( out, 
		(im_construct_fn) im_rotate_imask90,
		(im_callback_fn) im_free_imask, mask, mask->filename, NULL )) )
		return( -1 );

	if( im_conv( in, t[0], mask ) ||
		im_conv( in, t[1], rmask ) ||
		im_abs( t[0], t[2] ) ||
		im_abs( t[1], t[3] ) ||
		im_add( t[2], t[3], out ) )
		return( -1 );

	return( 0 );
}
