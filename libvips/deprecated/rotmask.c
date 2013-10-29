/* Functions to create offsets for rotating square masks.
 *
 * Author: N. Dessipris (Copyright, N. Dessipris 1991)
 * Written on: 08/05/1991
 * Modified on: 28/05/1991
 * 12/10/95 JC
 *	- small revisions, needs rewriting really
 * 7/8/96 JC
 *	- absolutely foul desp code revised
 *	- many bugs and mem leaks fixed
 * 1/3/99 JC
 *	- oops, fns were not preserving scale and offset
 * 1/12/10
 * 	- allow any size mask for the 90 degree rotates by using im_rot90().
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
#define PIM_RINT 1
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <math.h>

#include <vips/vips.h>

/* The type of the vips operations we support.
 */
typedef int (*vips_fn)( IMAGE *in, IMAGE *out );

/* Pass a mask through a vips operation, eg. im_rot90().
 */
static INTMASK *
vapplyimask( INTMASK *in, const char *name, vips_fn fn )
{
	IMAGE *x;
	IMAGE *t[2];
	DOUBLEMASK *d[2];
	INTMASK *out;

	if( !(x = im_open( name, "p" )) )
		return( NULL );
	if( !(d[0] = im_local_dmask( x, im_imask2dmask( in, name ) )) ||
		im_open_local_array( x, t, 2, name, "p" ) ||
		im_mask2vips( d[0], t[0] ) ||
		fn( t[0], t[1] ) ||
		!(d[1] = im_local_dmask( x, im_vips2mask( t[1], name ) )) ||
		!(out = im_dmask2imask( d[1], name )) ) {
		im_close( x );
		return( NULL );
	}
	im_close( x );

	out->scale = in->scale;
	out->offset = in->offset;

	return( out );
}

static DOUBLEMASK *
vapplydmask( DOUBLEMASK *in, const char *name, vips_fn fn )
{
	IMAGE *x;
	IMAGE *t[2];
	DOUBLEMASK *out;

	if( !(x = im_open( name, "p" )) )
		return( NULL );
	if( im_open_local_array( x, t, 2, name, "p" ) ||
		im_mask2vips( in, t[0] ) ||
		fn( t[0], t[1] ) ||
		!(out = im_vips2mask( t[1], name )) ) {
		im_close( x );
		return( NULL );
	}
	im_close( x );

	out->scale = in->scale;
	out->offset = in->offset;

	return( out );
}

INTMASK *
im_rotate_imask90( INTMASK *in, const char *filename )
{
	return( vapplyimask( in, filename, im_rot90 ) );
}

DOUBLEMASK *
im_rotate_dmask90( DOUBLEMASK *in, const char *filename )
{
	return( vapplydmask( in, filename, im_rot90 ) );
}

static int 
im_rot45( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_rot45( in, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

INTMASK *
im_rotate_imask45( INTMASK *in, const char *filename )
{
	return( vapplyimask( in, filename, im_rot45 ) );
}

DOUBLEMASK *
im_rotate_dmask45( DOUBLEMASK *in, const char *filename )
{
	return( vapplydmask( in, filename, im_rot45 ) );
}
