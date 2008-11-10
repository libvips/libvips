/* @(#) Extract a tile from a pyramid as a jpeg
 * @(#)
 * @(#) int 
 * @(#) im_bernd( const char *tiffname, 
 * @(#) 	int x, int y, int w, int h )
 * @(#)
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * 7/5/99 JC
 *	- from im_tiff2vips and im_vips2jpeg, plus some stuff from Steve
 * 11/7/01 JC
 *	- page number now in filename
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static int
extract( IMAGE *in, int x, int y, int w, int h )
{
	int len;
	char *buf;
	IMAGE *t1 = im_open_local( in, "im_bernd:2", "p" );

	if( im_extract_area( in, t1, x, y, w, h ) ||
		im_vips2bufjpeg( t1, in, 75, &buf, &len ) )
		return( -1 );

	if( fwrite( buf, sizeof( char ), len, stdout ) != len ) {
		im_error( "im_bernd", "%s", _( "error writing output" ) );
		return( -1 );
	}
	fflush( stdout );

	return( 0 );
}

int
im_bernd( const char *tiffname, int x, int y, int w, int h )
{
	IMAGE *in;

	if( !(in = im_open( "im_bernd:1", "p" )) )
		return( -1 );
	if( im_tiff2vips( tiffname, in ) ||
		extract( in, x, y, w, h ) ) {
		im_close( in );
		return( -1 );
	}
	im_close( in );

	return( 0 );
}
