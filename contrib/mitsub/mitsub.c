/*
 * Version which sents raw data to the printer, which enlarges and centers.
 * Works for monochrome and four band IM_TYPE_CMYK images. Uses putc instead of
 * fprintf. Sents data straight to the printer. If enlargement, it is full and
 * x and y ratios are the same (aspect ratio is not changed)
 *
 * Helene Chahine, July 95
 *
 * JC 4/8/95
 *	- small tidies and bug fixes
 * 	- now does 1, 3 and 4 band
 * 	- resets printer after use
 * JC 1/9/95
 *	- colour reverse mode added
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
#include <string.h>

#include <vips/vips.h>
#include <vips/util.h>

#define NBPRINT 1	/* Maximun 15 copies */
#define VMAX 2904	/* Number of horizontal pixels */
#define HMAX 2368	/* Number of vertical pixels */

int
main( int argc, char *argv[] )
{
	int enlar = 0;
	int center = 0;
	int rev = 0;

	IMAGE *vips;
	FILE *out;
	int n1, n2;
	int x, y;
	int xsize, ysize;
	int c;
	PEL *p;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );

	while( --argc > 0 && (*++argv)[0] == '-' )
		while( (c = *++argv[0]) )
			switch( c ) {
			case 'e':
				enlar = 1;
				break;

			case 'c':
				center = 1;
				break;

			case 'r':
				rev = 1;
				break;

			default:
				error_exit( "mitsub: illegal option %c", c );
			}

	if( argc != 2 )
		error_exit( "usage: mitsub [-ecr] vipsfile mitfile\n"
			"where:\n"
			"\tvipsfile may be 1, 3 or 4 bands for mono, IM_TYPE_RGB or "
			"IM_TYPE_CMYK printing\n" 
			"\tmitfile may be '-', meaning send to stdout\n"
			"\t-e means enlarge to fill page\n"
			"\t-c means centre within page\n"
			"\t-r means reverse black/white\n"
			"\tNOTE: data is sent raw, with 0 == no ink - all correction is up to "
			"you\n"
			"example:\n"
			"\t%% mitsub -ec fred.v - > /dev/bpp0" );

	if( !(vips = im_open( argv[0], "r" )) )
		error_exit( "mitsub: unable to open \"%s\" for input", 
			argv[0] );

	if( strcmp( argv[1], "-" ) == 0 )
		out = stdout;
	else if( !(out = fopen( argv[1], "w" )) )
		error_exit( "mitsub: unable to open \"%s\" for output", 
			argv[1] );

	if( vips->Coding != IM_CODING_NONE || vips->BandFmt != IM_BANDFMT_UCHAR )
		error_exit( "mitsub: uncoded uchar only" );
	if( vips->Bands != 1 && vips->Bands != 3 && vips->Bands != 4 )
		error_exit( "mitsub: 1,3 and 4 band images only" );

	/* Set xsize and ysize.
	 */
	if( vips->Xsize <= vips->Ysize ) {
		xsize = vips->Xsize;
		ysize = vips->Ysize;
	}
	else {
		im_diagnostics( "mitsub: rotating ..." );
		xsize = vips->Ysize;
		ysize = vips->Xsize;
	}

	/* Shrink if image is too big.
	 */
	if( xsize > HMAX || ysize > VMAX ) {
		double x_factor = HMAX/xsize;
		double y_factor = VMAX/ysize;
		double factor = IM_MAX( x_factor, y_factor );
		IMAGE *sh = im_open( "shrink", "t" );

		im_diagnostics( "mitsub: shrinking by %g ...", factor );
		if( !sh || im_shrink( vips, sh, factor, factor ) )
			error_exit( "mitsub: shrink failed" );

		vips = sh;
		enlar = 0;
	}

	/* On line command and buffer clear.
	 */
 	putc( 0x11, out );
	putc( 0x1b, out );
	putc( 'Z', out );

	/* Memory clear.
	 */
	putc( 0x1b, out );
	putc( 'Z', out );

	/* Media size. (Size A4)
	 */
	putc( 0x1b, out );
	putc( '#', out );
	putc( 'P', out );
	putc( '0', out );

	/* Enlargement.
	 */
	if( enlar ) {
		double rh, rv;
		int n, m;

		/* Enlarge method: ('0'=simple enlargement, 
		 * '1'=linear enlargement)
		 */
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'O', out );
		putc( '1', out );	

		rh = HMAX/(double) xsize;
		rv = VMAX/(double) ysize;
		if( rh > 8 || rv > 8 ) {
			n = 8;
			m = 1;
		}
		else if( rh > rv ) {
			double fact = VMAX/255;

			n = 255;
			m = (int) ysize/fact + 1;
		}
		else {
			double fact = HMAX/255;

			n = 255;
			m = (int) xsize/fact + 1;
		}
		im_diagnostics( "mitsub: enlarging by %g ...", (double) n/m );

		/* Horizontal enlarge.
		 */	
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'P', out );
		putc( n, out );
		putc( m, out );

		/* Vertical enlarge.
		 */
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'Q', out );
		putc( n, out );
		putc( m, out );

	}
	else {
		/* No enlargement.
		 */
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'O', out );
		putc( '1', out );	
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'P', out );
		putc( 1, out );
		putc( 1, out );
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'Q', out );
		putc( 1, out );
		putc( 1, out );
	}

	if( rev ) {
		/* Colour reversing.
		 */
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'W', out );
		putc( '2', out  );
	}
	else {
		/* No reverse.
		 */
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'W', out );
		putc( '0', out  );
	}

	/* Number of copies.
	 */
	putc( 0x1b, out );
	putc( '#', out );
	putc( 'C', out );
	putc( NBPRINT, out  );

	/* Left margin.
	 */
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'S', out );
	putc( 0, out  );

	/* Top margin.
	 */
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'T', out );
	putc( 0, out  );

	/* Centering. ('1' = centering available, '0'= no centering).
	 */
	if( center ) {
		im_diagnostics( "mitsub: centering ..." );
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'C', out );
		putc( '1', out );	 
	}
	else {
		/* No centering.
		 */
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'C', out );
		putc( '0', out );
	}

	/* Transfer format = pixel order method for colour, = frame order 
	 * method for monochrome.
	 */	
	switch( vips->Bands ) {
	case 3:
	case 4:
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'A', out );
		putc( '2', out  );
		break;

	case 1:
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'A', out );
		putc( '0', out  );	
		break;

	default:
		error_exit( "internal error" );
		/*NOTREACHED*/
	}

	/* Colour specification.
	 */
	switch( vips->Bands ) {
	case 4:
	case 1:
		/* IM_TYPE_CMYK. For mono, send just K.
		 */
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'I', out );
		putc( '2', out );
		break;

	case 3:
		/* IM_TYPE_RGB.
		 */
		putc( 0x1b, out );
		putc( '&', out );
		putc( 'I', out );
		putc( '0', out );
		break;
	
	default:
		error_exit( "internal error" );
		/*NOTREACHED*/
	}

	/* Gray scale level.
	 */
	putc( 0x1b, out );
	putc( '#', out );
	putc( 'L', out );
	putc( 8, out );

	/* Rotation.
	 */
	if( vips->Xsize <= vips->Ysize ) {
		putc( 0x1b, out );
		putc( '#', out );
		putc( 'R', out );
		putc( '0', out );
	}
	else  {
		putc( 0x1b, out );
		putc( '#', out );
		putc( 'R', out );
		putc( '1', out );
	}
		
	/* Horizontal shift.
	 */ 
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'J', out );
	putc( 0, out );
	putc( 0, out );

	/* Vertical shift.
	 */
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'K', out );
	putc( 0, out );
	putc( 0, out );

	/* Number of horizontal pixels.
	 */
	n1 = vips->Xsize >> 8;
	n2 = vips->Xsize & 0xff;
	putc(  0x1b, out );
	putc( '&', out );
	putc( 'H', out );
	putc( n1, out );
	putc( n2, out );
	
	/* Number of vertical pixels.
	 */
	n1 = vips->Ysize >> 8;
	n2 = vips->Ysize & 0xff;
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'V', out );
	putc( n1, out );
	putc( n2, out );

	/* Transfer colour (for monochrome image only).
	 */
	if( vips->Bands == 1 ) {
		putc( 0x1b, out );
		putc( 'C', out );
		putc( '4', out );
	}

	/* Image data transfer. Image must be sent as YMCK.
	 */
	putc( 0x1b, out );
	putc( 'O', out );
	if( im_incheck( vips ) )
		error_exit( "mitsub: unable to read image data" );
	p = (PEL *) vips->data;
	switch( vips->Bands ) {
	case 4:
		im_diagnostics( "mitsub: sending IM_TYPE_CMYK ..." );
		for( y = 0; y < vips->Ysize; y++ )
			for( x = 0; x < vips->Xsize; x++ ) {
 				putc( p[2], out );
				putc( p[1], out );
				putc( p[0], out );
				putc( p[3], out );
				p += 4;
			}
		break;

	case 3:
		im_diagnostics( "mitsub: sending IM_TYPE_RGB ..." );
		for( y = 0; y < vips->Ysize; y++ )
			for( x = 0; x < vips->Xsize; x++ ) {
 				putc( p[0], out );
				putc( p[1], out );
				putc( p[2], out );
				p += 3;
			}
		break;

	case 1:
		im_diagnostics( "mitsub: sending K ..." );
		for( y = 0; y < vips->Ysize; y++ )
			for( x = 0; x < vips->Xsize; x++ )
 				putc( *p++, out );
		break;
	}

	/* Form feed. Page end.
	 */
	putc( 0x0c, out  );

	/* Now try to reset printer to default settings. 
	 *
	 * No enlargement.
	 */
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'O', out );
	putc( '1', out );	
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'P', out );
	putc( 1, out );
	putc( 1, out );
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'Q', out );
	putc( 1, out );
	putc( 1, out );

	/* No centering.
	 */
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'C', out );
	putc( '0', out );

	/* No colour reverse.
	 */
	putc( 0x1b, out );
	putc( '&', out );
	putc( 'W', out );
	putc( '0', out  );

	return( 0 );
}

