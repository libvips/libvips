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

/* Creates the offsets to rotate by 45 degrees an odd size square mask 
 */
int *
im_offsets45( int size )
{
	int temp;
	int x, y;
	int size2 = size * size;
	int size_2 = size / 2;
	int *pnt, *cpnt1, *cpnt2;

	if( size%2 == 0 ) {
		im_error( "im_offsets45", "%s", _( "size not odd" ) );
		return( NULL );
	}
	if( !(pnt = IM_ARRAY( NULL, size2, int )) ) 
		return( NULL );

	/* point at the beginning and end of the buffer
	 */
	cpnt1 = pnt; cpnt2 = pnt + size2 - 1;

	for( y = 0; y < size_2; y++ ) {
		temp = (size_2 + y) * size;
		*cpnt1++ = temp; 
		*cpnt2-- = size2 - 1 - temp;

		for( x = 0; x < y; x++ ) {
			temp -= (size-1);
			*cpnt1++ = temp; 
			*cpnt2-- = size2 - 1 - temp;
		}

		for( x = 0; x < size_2 - y; x++ ) {
			temp -= size;
			*cpnt1++ = temp; 
			*cpnt2-- = size2 - 1 - temp;
		}

		for( x = 0; x < size_2 - y; x++ ) {
			temp++;
			*cpnt1++ = temp; 
			*cpnt2-- = size2 - 1 - temp;
		}

		for( x = 0; x < y; x++ ) {
			temp -= ( size - 1 );
			*cpnt1++ = temp; 
			*cpnt2-- = size2 - 1 - temp;
		}
	}

	/* the diagonal now 
	 */
	temp = size * (size - 1);
	cpnt1 = pnt + size_2 * size;
	for( x = 0; x < size; x++ ) {
		*cpnt1++ = temp; 
		temp -= (size-1);
	}

#ifdef PIM_RINT
	temp = 0;
	for( y = 0; y < size; y++ ) {
		for( x = 0; x < size; x++ ) {
			fprintf( stderr, "%4d", *(pnt+temp) );
			temp++;
		}
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");
#endif

	return( pnt );
}

/**
 * im_rotate_dmask45:
 * @in: input matrix 
 * @filename: name for output matrix
 *
 * Returns a mask which is the argument mask rotated by 45 degrees.  
 * Pass the filename to set for the output.
 *
 * See also: im_rotate_dmask90().
 *
 * Returns: the result matrix on success, or %NULL on error.
 */
DOUBLEMASK *
im_rotate_dmask45( DOUBLEMASK *in, const char *filename )
{
	DOUBLEMASK *out;
	int size = in->xsize * in->ysize;
	int *offsets;
	int i;

	if( in->xsize != in->ysize || (in->xsize % 2) == 0 ) {
		im_error( "im_rotate_dmask45", "%s", 
			_( "mask should be square of odd size" ) );
		return( NULL );
	}
	if( !(offsets = im_offsets45( in->xsize )) )
		return( NULL );
	if( !(out = im_create_dmask( filename, in->xsize, in->ysize )) ) {
		im_free( offsets );
		return( NULL );
	}
	out->scale = in->scale;
	out->offset = in->offset;

	for( i = 0; i < size; i++ )
		out->coeff[i] = in->coeff[offsets[i]];

	im_free( offsets );

	return( out );
}

/**
 * im_rotate_imask45:
 * @in: input matrix 
 * @filename: name for output matrix
 *
 * Returns a mask which is the argument mask rotated by 45 degrees.  
 * Pass the filename to set for the output.
 *
 * See also: im_rotate_imask90().
 *
 * Returns: the result matrix on success, or %NULL on error.
 */
INTMASK *
im_rotate_imask45( INTMASK *in, const char *filename )
{
	INTMASK *out;
	int size = in->xsize * in->ysize;
	int *offsets;
	int i;

	if( in->xsize != in->ysize || (in->xsize % 2) == 0 ) {
		im_error( "im_rotate_imask45", "%s", 
			_( "mask should be square of odd size" ) );
		return( NULL );
	}
	if( !(offsets = im_offsets45( in->xsize )) )
		return( NULL );
	if( !(out = im_create_imask( filename, in->xsize, in->ysize )) ) {
		im_free( offsets );
		return( NULL );
	}
	out->scale = in->scale;
	out->offset = in->offset;

	for( i = 0; i < size; i++ )
		out->coeff[i] = in->coeff[offsets[i]];

	im_free( offsets );

	return( out );
}

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

/**
 * im_rotate_imask90:
 * @in: input matrix 
 * @filename: name for output matrix
 *
 * Returns a mask which is the argument mask rotated by 90 degrees.  
 * Pass the filename to set for the output.
 *
 * See also: im_rotate_imask45().
 *
 * Returns: the result matrix on success, or %NULL on error.
 */
INTMASK *
im_rotate_imask90( INTMASK *in, const char *filename )
{
	return( vapplyimask( in, filename, im_rot90 ) );
}

/**
 * im_rotate_dmask90:
 * @in: input matrix 
 * @filename: name for output matrix
 *
 * Returns a mask which is the argument mask rotated by 90 degrees.  
 * Pass the filename to set for the output.
 *
 * See also: im_rotate_dmask45().
 *
 * Returns: the result matrix on success, or %NULL on error.
 */
DOUBLEMASK *
im_rotate_dmask90( DOUBLEMASK *in, const char *filename )
{
	return( vapplydmask( in, filename, im_rot90 ) );
}
