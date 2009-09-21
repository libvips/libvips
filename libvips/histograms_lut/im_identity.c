/* @(#) Creates a image file with Xsize=256, Ysize=1, Bands=bands,
 * @(#) Bbits=IM_BBITS_BYTE, BandFmt=IM_BANDFMT_UCHAR, Type=IM_TYPE_HISTOGRAM;
 * @(#) 
 * @(#) The created image consist a n bands linear lut and is the basis 
 * @(#) for building up look-up tables.
 * @(#) 
 * @(#) int im_identity(lut, bands)
 * @(#) IMAGE *lut;
 * @(#) int bands;
 * @(#)
 * @(#) As above, but make a ushort LUT. ushort LUTs can be less than 65536
 * @(#) elements - sz is the number of elements required.
 * @(#)
 * @(#) int im_identity_ushort(lut, bands, sz)
 * @(#) IMAGE *lut;
 * @(#) int bands;
 * @(#) int sz;
 * @(#)
 * @(#) Returns -1 on error and 0 on success
 * @(#) 
 *
 * Copyright 1991, N. Dessipris.
 *
 * Author N. Dessipris
 * Written on 11/03/1991
 * Updated on: 
 * 18/6/93 JC
 *	- im_outcheck() call added
 *	- ANSIfied
 * 24/8/94 JC
 *	- im_identity_ushort() added
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
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_identity( IMAGE *lut, int bands )
{
	unsigned char *buf, *p;
	int x, z;

	/* Check input args 
	 */
	if( im_outcheck( lut ) ) 
		return( -1 );
	if( bands < 0 ) {
		im_error( "im_identity", "%s", _( "bad bands" ) ); 
		return( -1 ); 
	}

	/* Set new image properly.
	 */
	im_initdesc( lut, 
		256, 1, bands, IM_BBITS_BYTE, IM_BANDFMT_UCHAR,
		IM_CODING_NONE, IM_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );

	/* Make output.
	 */
	if( im_setupout( lut ) ) 
		return( -1 );

	/* Create output buffer.
	 */
	if( !(buf = (unsigned char *) im_malloc( lut, bands * 256 )) )  
		return( -1 ); 

	/* Write ramp.
	 */
	for( p = buf, x = 0; x < 256; x++ )
		for( z = 0; z < bands; z++ )
			*p++ = x;

	if( im_writeline( 0, lut, buf ) ) 
		return( -1 );

        return( 0 );
}

int 
im_identity_ushort( IMAGE *lut, int bands, int sz )
{
	unsigned short *buf, *p;
	int x, z;

	/* Check input args 
	 */
	if( im_outcheck( lut ) ) 
		return( -1 );
	if( sz > 65536 || sz < 0 ) {
		im_error( "im_identity_ushort", "%s", _( "bad size" ) ); 
		return( -1 ); 
	}
	if( bands < 0 ) {
		im_error( "im_identity_ushort", "%s", _( "bad bands" ) ); 
		return( -1 ); 
	}

	/* Set new image.
	 */
	im_initdesc( lut, 
		sz, 1, bands, IM_BBITS_SHORT, IM_BANDFMT_USHORT,
		IM_CODING_NONE, IM_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );

	/* Make output.
	 */
	if( im_setupout( lut ) ) 
		return( -1 );

	/* Create output buffer.
	 */
	if( !(buf = (unsigned short *) 
		im_malloc( lut, sz * bands * sizeof( unsigned short ) )) )  
		return( -1 ); 

	/* Write ramp.
	 */
	for( p = buf, x = 0; x < sz; x++ )
		for( z = 0; z < bands; z++ )
			*p++ = x;
	if( im_writeline( 0, lut, (PEL *) buf ) ) 
		return( -1 );

        return( 0 );
}
