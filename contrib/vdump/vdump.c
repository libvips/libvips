/* This is incredibly primitive and annoying.
 * 
 * Turn a VASARI format file into PostScript. Do simple subsampling of
 * images to get the size down .. no point in sending anything much larger
 * than 100x100 to the laserwriter if it's going in a document. The output
 * conforms to PS-Adobe-2.0 EPSF-2.0, I think.
 *
 * Options:
 *	-s<n>	Average an nxn area in the image for each pixel in the output.
 *		This reduces the size of the files significantly (obviously).
 *		Default 1.
 *	-l	Force landscape output
 *	-p	Force portrait output (default)
 *	-a	Automatic choice of portrait/landscape
 *		Nasty: as we have to include a %%BoundingBox: line, we can't
 *		size the image to fit comfortably in whatever size paper this
 *		PostScript printer takes.
 *	-D	Supress generation of showpage. Sometimes necessary if you 
 *		want to include the PS file in a document.
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

#include <vips/vips.h>
#include <vips/util.h>

#define USAGE "usage: [-s<scale> -alpD] vasari_format_file"
#define PROLOGUE "vdump.pro"
#define PAPER_WIDTH (8.25*72.0)		/* Paper size .. A4 */
#define PAPER_HEIGHT (11.75*72.0)
#define PAPER_MARGIN (1.0*72.0)		/* Margin we leave around the edge */
#define PRINT_WIDTH (PAPER_WIDTH - 2.0*PAPER_MARGIN)
#define PRINT_HEIGHT (PAPER_HEIGHT - 2.0*PAPER_MARGIN)
#define PRINT_RATIO (PRINT_WIDTH / PRINT_HEIGHT)

/* Useful: a pixel. We mmap the file, then cast the pointer to the image to
 * a pointer to one of these things.
 */
struct pixel {
	unsigned char p_red;
	unsigned char p_green;
	unsigned char p_blue;
};

/* A monochrome pixel.
 */
struct mpixel {
	unsigned char p_val;
};

enum output_format {
	LANDSCAPE,			/* Rotated by 90 degrees */
	PORTRAIT,			/* Vertical */
	AUTOMATIC			/* Whichever fits best */
};

static const char *our_name;		/* Name of this prog */
static char *file_name;			/* Name of file we dump */
static int print_on = 1;		/* Generate showpage */

/* Copy between two fds
 */
static void
copy_file( from, to )
FILE *from, *to;
{	int ch;

	while( (ch = getc( from )) != EOF )
		putc( ch, to );
}

/* Send a file to stdout. Used to transmit the prelude.
 */
static int
transmit_file( name )
char *name;
{	const char *prefix;
	char buf[PATH_MAX];
	FILE *fp;

	if( !(prefix = im_guess_prefix( our_name, "VIPSHOME" )) )
		error_exit( "VIPSHOME not defined" );
	im_snprintf( buf, PATH_MAX, "%s/share/%s/%s", prefix, PACKAGE, name );

	/* Send it!
	 */
	if( !(fp = fopen( buf, "r" )) )
		error_exit( "can't find %s", name );
	copy_file( fp, stdout );
	fclose( fp );

	return( -1 );
}

/* Encode a colour VASARI file as mono hex bytes. Scale down by a factor of
 * s. We scale by averaging regions of sxs pixels .. is this the best way?
 * works ok for our laserwriter anyway. We lose incomplete regions down the RH
 * side and across the bottom.
 */
static void
encode_colour( im, s, data )
IMAGE *im;
int s;
struct pixel *data;
{	int p = 35;
	int x, y;
	int i, j;
	
	/* Scan across and down. Make sure we chop off those incomplete
	 * regions on the RH side and across the bottom.
 	 */
	for( y = 0; y <= im->Ysize - s; y += s )
		for( x = 0; x <= im->Xsize - s; x += s ) {
			int col = 0;
			struct pixel *rs = &data[y * im->Xsize + x];

			/* Now average the region. We monochromise each pixel
			 * and add it to the running total.
			 */
			for( i = 0; i < s; i++ ) {
				struct pixel *d = &rs[i * im->Xsize];

				for( j = 0; j < s; j++ ) {
					col += (int) (d->p_red + d->p_green +
						d->p_blue) / 3;
					d++;
				}
			}
			col /= s*s;

			/* Output the averaged pixel.
			 */
			printf( "%02x", col );
			if( !p-- ) {
				printf( "\n" );
				p = 35;
			}
		}
	printf( "\n" );
}

/* Encode a mono VASARI file as hex bytes. Scale down by a factor of
 * s. We scale by averaging regions of sxs pixels .. is this the best way?
 * works ok for our laserwriter anyway. We lose incomplete regions down the RH
 * side and across the bottom.
 */
static void
encode_mono( im, s, data )
IMAGE *im;
int s;
struct mpixel *data;
{	int p = 35;
	int x, y;
	int i, j;
	
	/* Scan across and down. Make sure we chop off those incomplete
	 * regions on the RH side and across the bottom.
 	 */
	for( y = 0; y <= im->Ysize - s; y += s )
		for( x = 0; x <= im->Xsize - s; x += s ) {
			int col = 0;
			struct mpixel *rs = &data[y * im->Xsize + x];

			/* Now average the region. 
			 */
			for( i = 0; i < s; i++ ) {
				struct mpixel *d = &rs[i * im->Xsize];

				for( j = 0; j < s; j++ )
					col += d++->p_val;
			}
			col /= s*s;

			/* Output the averaged pixel.
			 */
			printf( "%02x", col );
			if( !p-- ) { printf( "\n" ); p = 35; }
		}
	printf( "\n" );
}

/* Print the image. Work out the orientation, print the prologue, then call
 * one of the dumps above to do the image. 
 */
static void
dump( im, format, scale )
IMAGE *im;
enum output_format format;
int scale;
{	float r, width, height, xstart, ystart;

	/* Fix orientation, then set our origin and output size. Four cases ..
	 * can any of these be combined? Perhaps not.
	 */
	r = (float) im->Xsize / im->Ysize;
	if( format == AUTOMATIC ) {
		if( im->Xsize > im->Ysize )
			format = LANDSCAPE;
		else
			format = PORTRAIT;
	}

	if( format == PORTRAIT ) {
		/* Is it going to be smaller than the paper vertically or
		 * horizontally? 
		 */
		if( r > PRINT_RATIO ) {
			/* It's too wide. We make it as large as possible
			 * horizontally, then center it vertically.
			 */
			width = PRINT_WIDTH;
			height = PRINT_WIDTH / r;
			xstart = PAPER_MARGIN;
			ystart = (PRINT_HEIGHT - height) / 2.0 + PAPER_MARGIN;
		}
		else {
			/* Too high. Make as large as possible vertically,
			 * then center it horizontally.
			 */
			height = PRINT_HEIGHT;
			width = PRINT_HEIGHT * r;
			ystart = PAPER_MARGIN;
			xstart = (PRINT_WIDTH - width) / 2.0 + PAPER_MARGIN;
		}
	}
	else {
		/* Do a landscape picture. Will we run out of space
		 * horizontally or vertically? 
		 */
		if( 1.0 / r < PRINT_RATIO ) {
			/* Very wide indeed! Fit it horizontally, then center
			 * it vertically.
			 */
			height = PRINT_HEIGHT;
			width = PRINT_HEIGHT / r;
			ystart = PAPER_MARGIN;
			xstart = (PRINT_WIDTH - width) / 2.0 + PAPER_MARGIN;
		}
		else {
			/* Too tall. Make as large as possible vertically,
			 * then center it horizontally.
			 */
			width = PRINT_WIDTH;
			height = PRINT_WIDTH * r;
			xstart = PAPER_MARGIN;
			ystart = (PRINT_HEIGHT - height) / 2.0 + PAPER_MARGIN;
		}
	}

	/* Print header.
	 */
	printf( "%%!PS-Adobe-2.0 EPSF-2.0\n" ); 
	printf( "%%%%BoundingBox: %d %d %d %d\n", (int) xstart, (int) ystart, 
		(int) (width + xstart), (int) (height + ystart) );
	printf( "%%%%Title: %s\n", file_name );
	printf( "%%%%Creator: %s\n", our_name );

	/* Print prologue.
	 */
	transmit_file( PROLOGUE );

	/* Print position, scale and rotation. Print size in pixels and call
	 * doimage.
	 */
	if( format == LANDSCAPE )
		printf( "%d %d translate\n", 
			(int) (xstart + width), (int) ystart );
	else 
		printf( "%d %d translate\n", (int) xstart, (int) ystart );
	printf( "%d %d scale\n", (int) width, (int) height );
	if( format == LANDSCAPE )
		printf( "90 rotate\n" );
	printf( "%d %d 8 doimage\n", 
		(int) (im->Xsize / scale), (int) (im->Ysize / scale) );

	/* Print body of file.
	 */
	if( im->Bands == 3 )
		encode_colour( im, scale, (struct pixel *) im->data );
	else
		encode_mono( im, scale, (struct mpixel *) im->data );
	
	/* Print trailer.
	 */
	if( print_on )
		printf( "showpage\n" );
	printf( "%%%%EndDocument\n" );
}

/* Start here!
 */
int
main( argc, argv )
int argc; 
char **argv;
{	int scale = 1;
	enum output_format format = PORTRAIT;
	IMAGE *im = NULL;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );

	our_name = *argv;

	/* Decode args .. just look for file names and our three options.
	 */
	while( --argc )
		if( *argv[argc] == '-' )
			switch( argv[argc][1] ) {
			case 's':	
				if( sscanf( argv[argc] + 2, 
					"%d", &scale ) != 1 )
					error_exit( USAGE );
				break;

			case 'l':
				format = LANDSCAPE;
				break;

			case 'p':
				format = PORTRAIT;
				break;

			case 'a':
				format = AUTOMATIC;
				break;

			case 'D':
				print_on = 0;
				break;

			default:
				error_exit( USAGE );
				break;
			}
		else {
			/* Try to open the file. If we have previously opened,
			 * then flag an error.
			 */
			if( im != NULL )
				error_exit( USAGE );
			file_name = argv[argc];
			if( !(im = im_open( file_name, "r" )) )
				error_exit( "unable to open %s", file_name );
		}
	if( im == NULL ) error_exit( USAGE );

	/* Check it for suitability. We can print colour
	 * or monochrome pictures.
	 */
	if( im->Coding != IM_CODING_NONE ) 
		error_exit( "cannot print compressed pictures" );
	if( !(
		(im->Bands == 3 && im->Bbits == 8 && 
			im->BandFmt == IM_BANDFMT_UCHAR) ||
		(im->Bands == 1 && im->Bbits == 8 && 
			im->BandFmt == IM_BANDFMT_UCHAR)
		) )
		error_exit( "can only print mono or colour images" );
	if( im_incheck( im ) )
		error_exit( "unable to get pixels" );
	
	dump( im, format, scale);

	return( 0 );
}
