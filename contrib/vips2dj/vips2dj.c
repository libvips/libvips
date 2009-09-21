/* Convert lab, cmyk and mono images to postscript.
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
#include <limits.h>

#include <vips/vips.h>
#include <vips/util.h>

#include "vips2dj.h"

static const char *argv0 = NULL;

/* Geometries for the printers we know about.
 */
PrinterGeometry printer_data[] = {
	/* name, paper width, print width, print length, left, top */
	{ "2500cp", 2592, 2502, 3728, 51, 82 },
	{ "3500cp", 3888, 3786, 5212, 51, 82 },
	{ "5000ps", 4320, 4280, 5212, 20, 99 },
	{ "4600dn", 595, 570, 817, 11, 15 },
	{ "4700n", 595, 569, 816, 17, 14 }
};

/* Print a geo entry.
 */
static void
print_printers( void )
{
	int i;

	printf( "%12s %12s %12s %12s %12s %12s\n", "printer name", 
		"paper width", "print width", "print length",
		"left margin", "top margin" );
	for( i = 0; i < IM_NUMBER( printer_data ); i++ ) 
		printf( "%12s %12d %12d %12d %12d %12d\n",
			printer_data[i].name,
			printer_data[i].pwidth,
			printer_data[i].width,
			printer_data[i].length,
			printer_data[i].left,
			printer_data[i].top );
}

/* Turn a name to a printer geometry.
 */
static PrinterGeometry *
find_printer( char *name )
{
	int i;

	for( i = 0; i < IM_NUMBER( printer_data ); i++ )
		if( strcmp( name, printer_data[i].name ) == 0 )
			return( &printer_data[i] );
	
	im_error( "vips2dj", _( "unknown printer \"%s\"" ), name );
	return( NULL );
}

/* Copy between two fds
 */
static int
copy_bytes( FILE *in, FILE *out )
{	
	int ch;

	while( (ch = getc( in )) != EOF )
		if( putc( ch, out ) == EOF ) {
			im_error( "vips2dj", "%s", 
				_( "write error -- disc full?" ) );
			return( -1 );
		}
	
	return( 0 );
}

/* Send a file to out. Used to transmit the preludes.
 */
static int
transmit_file( char *mode, char *name, FILE *out )
{
	const char *prefix;
	char buf[PATH_MAX];
	FILE *in;

	if( !(prefix = im_guess_prefix( argv0, "VIPSHOME" )) )
		return( -1 );

	/* Send it!
	 */
	im_snprintf( buf, PATH_MAX, "%s/share/vips/vips2dj/%s/%s", 
		prefix, mode, name );
	if( !(in = fopen( buf, "r" )) ) {
		im_error( "vips2dj", _( "can't find \"%s\"" ), name );
		return( -1 );
	}
	if( copy_bytes( in, out ) ) {
		fclose( in );
		return( -1 );
	}
	fclose( in );

	return( 0 );
}

/* Send the file to fp. width and height are the size to print at in points.
 */
static int
send_file( PrinterGeometry *geo, IMAGE *im, char *mode, 
	FILE *out, int width, int height )
{
	/* Send all the start stuff.
	 */
	if( transmit_file( mode, "head1", out ) )
		return( -1 );
	
	/* Set page size. 
	 */
	fprintf( out, "<</PageSize[%d %d]/ImagingBBox null>>setpagedevice\n",
		geo->pwidth, height + 2*geo->top );

	if( transmit_file( mode, "head2", out ) )
		return( -1 );

	/* Set mT (margin transform? don't know)
	 */
	fprintf( out, "/mT[1 0 0 -1 %d %d]def\n", 
		geo->left, height + geo->top );

	if( transmit_file( mode, "head3", out ) )
		return( -1 );

	/* Set rC ... printable area.
	 */
	fprintf( out, "gS 0 0 %d %d rC\n", width, height );

	if( transmit_file( mode, "head4", out ) )
		return( -1 );

	/* Set image params.
	 */
	fprintf( out, "/rows %d def\n", im->Ysize );
	fprintf( out, "/cols %d def\n", im->Xsize );
	fprintf( out, "%d %d scale\n", width, height );

	if( transmit_file( mode, "head5", out ) )
		return( -1 );

	/* Send the body of the image.
	 */
	if( vips2asciihex( im, out ) )
		return( -1 );

	if( transmit_file( mode, "head6", out ) )
		return( -1 );

	return( 0 );
}

/* Start here!
 */
int
main( int argc, char **argv )
{	
	IMAGE *im = NULL;
	FILE *out = stdout;
	int width = -1;
	int height = -1;
	int dpi = -1;
	int max = 0;
	int rotate = 0;
	int one2one = 0;
	PrinterGeometry *geo = find_printer( "2500cp" );
	char *mode;
	int i;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );

	argv0 = argv[0];

	if( argc <= 1 ) {
		printf( 
"usage:\n"
"\t%s [options] <image file>\n"
"convert RGB, LAB, CMYK and mono image files to postscript\n"
"\tRGB converted to LAB, assuming sRGB\n"
"\tLAB printed with printer colour management\n"
"\tCMYK sent directly as dot percent\n"
"\tmono prints as K only\n"
"options include:\n"
"\t-printer <name>\tformat for printer <name>\n"
"\t-3500cp\t\tfor HP 3500CP printer (default 2500cp)\n"
"\t-max\t\tprint as large as possible\n"
"\t-rotate\t\trotate, if necessary, to fill the page\n"
"\t-1:1\t\tsize the image to print at 1:1 ... resolution in\n"
"\t\t\timage header must be set for this\n"
"\t-width <n>\tforce specified width, in points\n"
"\t-height <n>\tforce specified height, in points\n"
"\t-dpi <n>\tforce specified resolution (default 150dpi)\n"
"\t-a5, -a4, -a3, -a2, -a1, -a0\n"
"\t\t\tforce specified height (width ignored)\n"
"\t-o <file>\toutput to file (default stdout)\n",
			argv0 );
		printf( "supported printers:\n" );
		print_printers();
		return( 1 );
	}

	/* Decode args .. just look for file names and our three options.
	 */
	for( i = 1; i < argc; i++ )
		if( *argv[i] == '-' ) {
			if( strcmp( argv[i]+1, "width" ) == 0 ) {
				if( !argv[i+1] || sscanf( argv[i+1], 
					"%d", &width ) != 1 || width <= 10 )
					error_exit( "bad width" );
				i++;
			}
			else if( strcmp( argv[i]+1, "height" ) == 0 ) {
				if( !argv[i+1] || sscanf( argv[i+1], 
					"%d", &height ) != 1 || height <= 10 )
					error_exit( "bad height" );
				i++;
			}
			else if( strcmp( argv[i]+1, "3500cp" ) == 0 ) {
				geo = find_printer( "3500cp" );
			}
			else if( strcmp( argv[i]+1, "printer" ) == 0 ) {
				if( !argv[i+1] || 
					!(geo = find_printer( argv[i+1] )) )
					error_exit( "bad printer model" );
				i++;
			}
			else if( strcmp( argv[i]+1, "dpi" ) == 0 ) {
				if( !argv[i+1] || sscanf( argv[i+1], 
					"%d", &dpi ) != 1 || dpi <= 1 ||
					dpi >= 600 )
					error_exit( "bad dpi" );
				i++;
			}
			else if( strcmp( argv[i]+1, "o" ) == 0 ) {
				if( !argv[i+1] || !(out = fopen( 
					argv[i+1], "w" )) )
					error_exit( "bad output name" );
				i++;
			}
			else if( strcmp( argv[i]+1, "1:1" ) == 0 ) 
				one2one = 1;	
			else if( strcmp( argv[i]+1, "a5" ) == 0 ) 
				height = 595;
			else if( strcmp( argv[i]+1, "a4" ) == 0 ) 
				height = 839;
			else if( strcmp( argv[i]+1, "a3" ) == 0 ) 
				height = 1187;
			else if( strcmp( argv[i]+1, "a2" ) == 0 ) 
				height = 1678;
			else if( strcmp( argv[i]+1, "a1" ) == 0 ) 
				height = 2373;
			else if( strcmp( argv[i]+1, "a0" ) == 0 ) 
				height = 3356;
			else if( strcmp( argv[i]+1, "max" ) == 0 ) 
				max = 1;
			else if( strcmp( argv[i]+1, "rotate" ) == 0 ) 
				rotate = 1;
			else
				error_exit( "bad flag" );
		}
		else {
			/* Try to open the file. 
			 */
			if( im != NULL || !(im = im_open( argv[i], "r" )) )
				error_exit( "bad input image" );
		}

	if( im == NULL ) 
		error_exit( "no input image" );

	/* Turn 3-band uchar images into LABQ. Yuk! But convenient.
	 */
	if( im->Coding == IM_CODING_NONE &&
		im->Bands == 3 && im->BandFmt == IM_BANDFMT_UCHAR ) {
		IMAGE *t[3];

		if( im_open_local_array( im, t, 3, "vips2dj", "p" ) ||
			im_sRGB2XYZ( im, t[0] ) ||
			im_XYZ2Lab( t[0], t[1] ) ||
			im_Lab2LabQ( t[1], t[2] ) )
			error_exit( "error converting to LAB" );

		im = t[2];
	}

	/* Stop used-before-set complaints on mode.
	 */
	mode = "lab";

	/* Pick a PS mode.
	 */
	if( im->Coding == IM_CODING_LABQ )
		mode = "lab";
	else if( im->Coding == IM_CODING_NONE && 
		im->Bands == 4 && im->BandFmt == IM_BANDFMT_UCHAR )
		mode = "cmyk";
	else if( im->Coding == IM_CODING_NONE && 
		im->Bands == 1 && im->BandFmt == IM_BANDFMT_UCHAR )
		mode = "mono";
	else 
		error_exit( "unsupported image type "
			"(IM_CODING_LABQ, mono, IM_TYPE_CMYK only)" );

	/* Autorotate image to fill the page. We ought to get PS to do the
	 * rotate, really.
	 */
	if( rotate ) {
		float iaspect = (float) im->Xsize / im->Ysize;
		float paspect = (float) geo->width / geo->length;

		if( iaspect > paspect ) {
			IMAGE *t[1];

			if( im_open_local_array( im, t, 1, "vips2dj", "p" ) ||
				im_rot90( im, t[0] ) )
				error_exit( "error rotating" );

			im = t[0];
		}
	}

	/* Make sure width and height are both set.
	 */
	if( one2one ) {
		/* Set width/height from res.
		 */
		if( im->Xres <= 0 || im->Xres >= 100 ||
			im->Yres <= 0 || im->Yres >= 100 )
			error_exit( "uanble to print 1:1 - resolution not "
				"set in image" );

		height = (((im->Ysize / im->Yres) / 10.0) / 2.54) * 72.0;
		width = (((im->Xsize / im->Xres) / 10.0) / 2.54) * 72.0;
	}
	else if( max ) {
		float iaspect = (float) im->Xsize / im->Ysize;
		float paspect = (float) geo->width / geo->length;

		if( iaspect > paspect ) 
			/* Image aspect ratio > paper ... fit width.
			 */
			width = geo->width;
		else
			height = geo->length;
	}
	else if( dpi > 0 ) {
		/* Given res ... set width/height.
		 */
		height = (im->Ysize / (float) dpi) * 72.0;
		width = (im->Xsize / (float) dpi) * 72.0;
	}

	if( width >= 0 || height >= 0 ) {
		/* Given width or height or both --- set other one.
		 */
		if( height < 0 ) {
			float fdpi = im->Xsize / (width / 72.0);
			height = (im->Ysize / fdpi) * 72.0;
		}
		else {
			float fdpi = im->Ysize / (height / 72.0);
			width = (im->Xsize / fdpi) * 72.0;
		}
	}
	else {
		/* Nothing set ... default to 150 dpi.
		 */
		height = (im->Ysize / 150.0) * 72.0;
		width = (im->Xsize / 150.0) * 72.0;
	}

	if( send_file( geo, im, mode, out, width, height ) )
		error_exit( "error sending file" );

	return( 0 );
}
