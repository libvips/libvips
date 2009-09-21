/* Output IM_CODING_LABQ as band-separated ASCIIHEX for PostScript 
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

#include <vips/vips.h>
#include <vips/region.h>

static int
writeimage( REGION *ir, FILE *out )
{
	IMAGE *im = ir->im;
	int x, y, z;
	int l = 0;
	PEL *p;
	Rect area;

	/* Set up input area.
	 */
	area.left = 0;
	area.top = 0;
	area.width = im->Xsize;
	area.height = 1;

/* Write a byte.
 */
#define PUT( C ) {\
	int c1 = (C);\
	\
	if( putc( c1, out ) == EOF ) {\
		im_error( "vips2hp2500cp", "%s", _( "write error - disc full?" ) );\
		return( -1 );\
	}\
}

/* Write a hex character.
 */
#define writehexc( C ) {\
	int c = (C);\
	\
	if( c < 10 ) {\
		PUT( c + '0' );\
	}\
	else\
		PUT( (c - 10) + 'A' );\
}

/* Write a hex byte.
 */
#define writehexb( B ) { \
	int b = (B);\
	\
	writehexc( (b >> 4 ) & 0xf );\
	writehexc( b & 0xf );\
}

/* Output a hex byte, linefeed on eol.
 */
#define writewrap( B ) { \
	writehexb( B ); \
	if( l++ > 30 ) { \
		PUT( '\n' ); \
		l = 0; \
	} \
}

	/* Loop for each scan-line.
	 */
	for( y = 0; y < im->Ysize; y++ ) {
		/* Ask for this scan-line.
		 */
		area.top = y;
		if( im_prepare( ir, &area ) )
			return( -1 );
		p = (PEL *) IM_REGION_ADDR( ir, 0, y );

		if( im->Coding == IM_CODING_LABQ ) {
			/* Do L* ... easy.
			 */
			for( x = 0; x < im->Xsize; x++ )
				writewrap( p[x*4] );

			/* a* and b* ... more difficult. Photoshop uses 
			 * bizzare coding for a/b.
			 */
			for( z = 1; z < 3; z++ ) {
				for( x = 0; x < im->Xsize; x++ ) {
					int i = (signed char) p[x*4 + z];

					writewrap( i + 128 );
				}
			}
		}
		else if( im->Bands == 4 ) {
			for( z = 0; z < 4; z++ ) 
				for( x = 0; x < im->Xsize; x++ ) {
					int v = p[x*4 + z];

					writewrap( v );
				}

			/* Extra channel?? Just send zeros.
			 */
			for( x = 0; x < im->Xsize; x++ ) 
				writewrap( 0xff );
		}
		else if( im->Bands == 1 ) {
			for( x = 0; x < im->Xsize; x++ ) {
				int v = p[x];

				writewrap( v );
			}
		}
	}
	PUT( '\n' );

	return( 0 );
}
 
/* Start here!
 */
int
vips2asciihex( IMAGE *in, FILE *out )
{
	REGION *ir;

	if( im_pincheck( in ) )
		return( -1 );
	if( !(ir = im_region_create( in )) )
		return( -1 );

	if( writeimage( ir, out ) ) {
		im_region_free( ir );
		return( -1 );
	}
	im_region_free( ir );

	return( 0 );
}
