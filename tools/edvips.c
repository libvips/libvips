/* modify vips file header! - useful for setting resolution, coding...
very dangerous!
no way of setting non-used codes in variables like newxres
so need flags to show new parameter has been set.. boring
Copyright K.Martinez 30/6/93
29/7/93 JC
	-format added
	- ==0 added to strcmp!
17/11/94 JC
	- new header fields added
21/10/04
	- more header updates

22/8/05
 	- less-stupid-ified
20/9/05
	- rewritten with glib option parser, ready for xml options to go in
 
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <locale.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

/* We have to represent all header fields as char* so we can spot unset args
 * safely.
 */
static char *xsize = NULL;
static char *ysize = NULL;
static char *bands = NULL;
static char *format = NULL;
static char *interpretation = NULL;
static char *coding = NULL;
static char *xres = NULL;
static char *yres = NULL;
static char *xoffset = NULL;
static char *yoffset = NULL;
static char *endian = NULL;
static gboolean setext = FALSE;

static GOptionEntry entries[] = {
	{ "endian", 'n', 0, G_OPTION_ARG_STRING, &endian, 
		N_( "tag file as big or little-endian" ), NULL },
	{ "width", 'w', 0, G_OPTION_ARG_STRING, &xsize, 
		N_( "set width to N pixels" ), "N" },
	{ "height", 'h', 0, G_OPTION_ARG_STRING, &ysize, 
		N_( "set height to N pixels" ), "N" },
	{ "bands", 'b', 0, G_OPTION_ARG_STRING, &bands, 
		N_( "set Bands to N" ), "N" },
	{ "format", 'f', 0, G_OPTION_ARG_STRING, &format, 
		N_( "set BandFmt to F (eg. uchar, float)" ), "F" },
	{ "interpretation", 'i', 0, G_OPTION_ARG_STRING, &interpretation, 
		N_( "set interpretation to I (eg. xyz)" ), "I" },
	{ "coding", 'c', 0, G_OPTION_ARG_STRING, &coding, 
		N_( "set Coding to C (eg. labq)" ), "C" },
	{ "xres", 'X', 0, G_OPTION_ARG_STRING, &xres, 
		N_( "set Xres to R pixels/mm" ), "R" },
	{ "yres", 'Y', 0, G_OPTION_ARG_STRING, &yres, 
		N_( "set Yres to R pixels/mm" ), "R" },
	{ "xoffset", 'u', 0, G_OPTION_ARG_STRING, &xoffset, 
		N_( "set Xoffset to N pixels" ), "N" },
	{ "yoffset", 'v', 0, G_OPTION_ARG_STRING, &yoffset, 
		N_( "set Yoffset to N pixels" ), "N" },
	{ "setext", 'e', 0, G_OPTION_ARG_NONE, &setext, 
		N_( "replace extension block with stdin" ), NULL },
	{ "xsize", 'x', 0, G_OPTION_ARG_STRING, &xsize, 
		N_( "set Xsize to N (deprecated, use width)" ), "N" },
	{ "ysize", 'y', 0, G_OPTION_ARG_STRING, &ysize, 
		N_( "set Ysize to N (deprecated, use height)" ), "N" },
	{ "type", 't', 0, G_OPTION_ARG_STRING, &interpretation, 
		N_( "set Type to T (deprecated, use interpretation)" ), "T" },
	{ NULL }
};

static void
parse_pint( char *arg, int *out )
{
	/* Might as well set an upper limit.
	 */
	*out = atoi( arg );
	if( *out <= 0 || *out > 1000000 ) 
		error_exit( _( "'%s' is not a positive integer" ), arg );
}

int
main( int argc, char **argv )
{
	GOptionContext *context;
	GError *error = NULL;
	IMAGE *im;
	unsigned char header[IM_SIZEOF_HEADER];

	if( im_init_world( argv[0] ) )
	        error_exit( "%s", _( "unable to start VIPS" ) );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

	context = g_option_context_new( 
		_( "vipsfile - edit vipsfile header" ) );
	g_option_context_add_main_entries( context, entries, GETTEXT_PACKAGE );
	g_option_context_add_group( context, im_get_option_group() );
	if( !g_option_context_parse( context, &argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
		        g_error_free( error );
		}

		exit( -1 );
	}
	if( argc != 2 ) {
		fprintf( stderr, _( "usage: %s [OPTION...] vipsfile\n" ), 
			g_get_prgname() );
		exit( -1 );
	}

	if( !(im = im_init( argv[1] )) ||
		(im->fd = im__open_image_file( im->filename )) == -1 ) 
		error_exit( _( "could not open image %s" ), argv[1] );
	if( read( im->fd, header, IM_SIZEOF_HEADER ) != IM_SIZEOF_HEADER ||
		im__read_header_bytes( im, header ) ) 
		error_exit( _( "could not read VIPS header for %s" ), 
			im->filename );

	if( endian ) {
		if( strcmp( endian, "little" ) == 0 )
			im->magic = VIPS_MAGIC_INTEL;
		else if( strcmp( endian, "big" ) == 0 )
			im->magic = VIPS_MAGIC_SPARC;
		else 
			error_exit( _( "bad endian-ness %s, "
				"should be 'big' or 'little'" ), endian );
	}
	if( xsize ) 
		parse_pint( xsize, &im->Xsize );
	if( ysize ) 
		parse_pint( ysize, &im->Ysize );
	if( bands ) 
		parse_pint( bands, &im->Bands );
	if( format ) {
		VipsBandFormat f;

		if( (f = im_char2BandFmt( format )) < 0 )
			error_exit( _( "bad format %s" ), format );
		im->BandFmt = f;
		im->Bbits = im_bits_of_fmt( f );
	}
	if( interpretation ) {
		VipsInterpretation i;

		if( (i = im_char2Type( interpretation )) < 0 )
			error_exit( _( "bad interpretation %s" ), 
				interpretation );
		im->Type = i;
	}
	if( coding ) {
		VipsCoding c;

		if( (c = im_char2Coding( coding )) < 0 )
			error_exit( _( "bad coding %s" ), coding );
		im->Coding = c;
	}
	if( xres ) 
		im->Xres = atof( xres );
	if( yres ) 
		im->Yres = atof( yres );
	if( xoffset ) 
		im->Xoffset = atoi( xoffset );
	if( yoffset ) 
		im->Yoffset = atoi( yoffset );

	if( lseek( im->fd, 0, SEEK_SET ) == (off_t) -1 ) 
		error_exit( _( "could not seek on %s" ), im->filename );
	if( im__write_header_bytes( im, header ) ||
		im__write( im->fd, header, IM_SIZEOF_HEADER ) )
		error_exit( _( "could not write to %s" ), im->filename );

	if( setext ) {
		char *xml;
		unsigned int size;

		if( !(xml = im__file_read( stdin, "stdin", &size )) )
			error_exit( "%s", _( "could not get ext data" ) );

		/* Strip trailing whitespace ... we can get stray \n at the 
		 * end, eg. "echo | edvips --setext fred.v".
		 */
		while( size > 0 && isspace( xml[size - 1] ) )
			size -= 1;

		if( im__write_extension_block( im, xml, size ) )
			error_exit( "%s", _( "could not set extension" ) );
		im_free( xml );
	}

	im_close( im );

	vips_shutdown();

	return( 0 );
}

