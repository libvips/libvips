/* @(#)  Functions to create offsets for rotating square masks.
 * @(#) Usage 
 * @(#) int *im_offsets45( size )
 * @(#) int size;
 * @(#)
 * @(#) Returns an int pointer to valid offsets on sucess and -1 on error
 * @(#)
 * 
 * @(#) Usage 
 * @(#) int *im_offsets90( size )
 * @(#) int size;
 * @(#)
 * @(#) Returns an int pointer to valid offsets on sucess and -1 on error
 * @(#)
 *
 * @(#)  Functions to rotate square masks
 * @(#)
 * @(#) Usage 
 * @(#) INTMASK *im_rotate_imask45( mask, name )
 * @(#) INTMASK *mask;
 * @(#)
 * @(#) Returns an pointer to INTMASK which keeps the original mask rotated
 * @(#) by 45 degrees clockwise.
 * @(#) The filename member of the returned mask is set to name
 * @(#)
 * @(#) Usage 
 * @(#) DOUBLEMASK *im_rotate_dmask45( mask, name )
 * @(#) DOUBLEMASK *mask;
 * @(#)
 * @(#) Returns an pointer to INTMASK which keeps the original mask rotated
 * @(#) by 45 degrees clockwise.
 * @(#) The filename member of the returned mask is set to name
 * @(#)
 * @(#) Usage 
 * @(#) INTMASK *im_rotate_imask90( mask, name )
 * @(#) INTMASK *mask;
 * @(#)
 * @(#) Returns an pointer to INTMASK which keeps the original mask rotated
 * @(#) by 90 degrees clockwise.
 * @(#) The filename member of the returned mask is set to name
 * @(#)
 * @(#) Usage 
 * @(#) DOUBLEMASK *im_rotate_dmask90( mask, name )
 * @(#) DOUBLEMASK *mask;
 * @(#)
 * @(#) Returns an pointer to DOUBLEMASK which keeps the original mask rotated
 * @(#) by 90 degrees clockwise.
 * @(#) The filename member of the returned mask is set to name
 * @(#)
 *
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

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

/* Creates the offsets to rotate any mask by 90 degrees.
 */
int *
im_offsets90( int size )
{
	int temp;
	int x, y, k;
	int *offsets;

	if( !(offsets = IM_ARRAY( NULL, size*size, int )) )
		return( NULL );

	for( k = 0, y = 0; y < size; y++ ) {
		temp = size * (size - 1) + y;

		for( x = 0; x < size; x++, k++ ) {
			offsets[k] = temp;
			temp -= size;
		}
	}

	return( offsets );
}

/* Tye pf offset-generating function.
 */
typedef int *(*offset_fn)( int );

/* Rotate a dmask with a set of offsets.
 */
static DOUBLEMASK *
rotdmask( offset_fn fn, DOUBLEMASK *m, const char *name )
{
	DOUBLEMASK *out;
	int size = m->xsize * m->ysize;
	int *offsets;
	int i;

	if( m->xsize != m->ysize || (m->xsize % 2) == 0 ) {
		im_error( "im_rotate_mask", "%s", 
			_( "mask should be square of even size" ) );
		return( NULL );
	}
	if( !(offsets = fn( m->xsize )) )
		return( NULL );
	if( !(out = im_create_dmask( name, m->xsize, m->ysize )) ) {
		im_free( offsets );
		return( NULL );
	}
	out->scale = m->scale;
	out->offset = m->offset;

	for( i = 0; i < size; i++ )
		out->coeff[i] = m->coeff[offsets[i]];

	im_free( offsets );

	return( out );
}

/* Rotate an imask with a set of offsets.
 */
static INTMASK *
rotimask( offset_fn fn, INTMASK *m, const char *name )
{
	INTMASK *out;
	int size = m->xsize * m->ysize;
	int *offsets;
	int i;

	if( m->xsize != m->ysize || (m->xsize % 2) == 0 ) {
		im_error( "im_rotate_mask", "%s", 
			_( "mask should be square of even size" ) );
		return( NULL );
	}
	if( !(offsets = fn( m->xsize )) )
		return( NULL );
	if( !(out = im_create_imask( name, m->xsize, m->ysize )) ) {
		im_free( offsets );
		return( NULL );
	}
	out->scale = m->scale;
	out->offset = m->offset;

	for( i = 0; i < size; i++ )
		out->coeff[i] = m->coeff[offsets[i]];

	im_free( offsets );

	return( out );
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
	return( rotdmask( im_offsets90, in, filename ) );
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
	return( rotdmask( im_offsets45, in, filename ) );
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
	return( rotimask( im_offsets90, in, filename ) );
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
	return( rotimask( im_offsets45, in, filename ) );
}
