/* modify vips file header! - useful for setting resolution, coding...
 * very dangerous!
 *
 * no way of setting non-used codes in variables like newxres
 * so need flags to show new parameter has been set.. boring
 * Copyright K.Martinez 30/6/93
 *
 * 29/7/93 JC
 * 	- format added
 * 	- ==0 added to strcmp!
 * 17/11/94 JC
 * 	- new header fields added
 * 21/10/04
 * 	- more header updates
 * 22/8/05
 * 	- less-stupid-ified
 * 20/9/05
 * 	- rewritten with glib option parser, ready for xml options to go in
 * 18/6/20 kleisauke
 * 	- avoid using vips7 symbols
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
#include <glib/gi18n.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <locale.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

/* We have to represent all header fields as char * so we can spot unset args
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
static gboolean version = FALSE;

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
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &version, 
		N_( "print version" ), NULL },
	{ NULL }
};

static void
parse_pint( char *arg, int *out )
{
	/* Might as well set an upper limit.
	 */
	*out = atoi( arg );
	if( *out <= 0 || *out > 1000000 )
		vips_error_exit( _( "'%s' is not a positive integer" ), arg );
}

int
main( int argc, char **argv )
{
	GOptionContext *context;
	GOptionGroup *main_group;
	GError *error = NULL;
	VipsImage *im;
	unsigned char header[VIPS_SIZEOF_HEADER];

	if( VIPS_INIT( argv[0] ) )
	        vips_error_exit( "%s", _( "unable to start VIPS" ) );

#ifdef ENABLE_NLS
	textdomain( GETTEXT_PACKAGE );
#endif /* ENABLE_NLS */
	setlocale( LC_ALL, "" );

{
	char *basename;

	basename = g_path_get_basename( argv[0] );
	g_set_prgname( basename );
	g_free( basename );
}

	/* On Windows, argv is ascii-only .. use this to get a utf-8 version of
	 * the args.
	 */
#ifdef G_OS_WIN32
	argv = g_win32_get_command_line();
#endif /*G_OS_WIN32*/

	context = g_option_context_new( 
		_( "vipsedit - edit vips file header" ) );
	main_group = g_option_group_new( NULL, NULL, NULL, NULL, NULL );
	g_option_group_add_entries( main_group, entries );
	vips_add_option_entries( main_group ); 
	g_option_group_set_translation_domain( main_group, GETTEXT_PACKAGE );
	g_option_context_set_main_group( context, main_group );

#ifdef G_OS_WIN32
	if( !g_option_context_parse_strv( context, &argv, &error ) ) 
#else /*!G_OS_WIN32*/
	if( !g_option_context_parse( context, &argc, &argv, &error ) ) 
#endif /*G_OS_WIN32*/
	{
		vips_g_error( &error );

		exit( -1 );
	}

	/* On Windows, argc will not have been updated by
	 * g_option_context_parse_strv().
	 */
	for( argc = 0; argv[argc]; argc++ )
		;

	if( version ) 
		printf( "vips-%s\n", vips_version_string() );

	if( argc != 2 ) { 
		fprintf( stderr, _( "usage: %s [OPTION...] vips-file\n" ), 
			g_get_prgname() );

		exit( -1 );
	}

	if( !(im = vips_image_new_from_file( argv[1], NULL )) )
		vips_error_exit( _( "could not open image %s" ), argv[1] );

	vips__seek( im->fd, 0, SEEK_SET );
	if( read( im->fd, header, VIPS_SIZEOF_HEADER ) !=
		VIPS_SIZEOF_HEADER ||
		vips__read_header_bytes( im, header ) )
		vips_error_exit( _( "could not read VIPS header for %s" ),
			im->filename );

	if( endian ) {
		if( strcmp( endian, "little" ) == 0 )
			im->magic = VIPS_MAGIC_INTEL;
		else if( strcmp( endian, "big" ) == 0 )
			im->magic = VIPS_MAGIC_SPARC;
		else
			vips_error_exit( _( "bad endian-ness %s, "
				"should be 'big' or 'little'" ), endian );
	}
	if( xsize ) 
		parse_pint( xsize, &im->Xsize );
	if( ysize ) 
		parse_pint( ysize, &im->Ysize );
	if( bands ) 
		parse_pint( bands, &im->Bands );
	if( format ) {
		int f;

		if( (f = vips_enum_from_nick( argv[0],
				VIPS_TYPE_BAND_FORMAT, format )) < 0 )
			vips_error_exit( _( "bad format %s" ), format );

		im->BandFmt = f;

		/* We don't use this, but make sure it's set in case any 
		 * old binaries are expecting it.
		 */
		im->Bbits = vips_format_sizeof( f ) << 3;
	}
	if( interpretation ) {
		int i;

		if( (i = vips_enum_from_nick( argv[0], 
				VIPS_TYPE_INTERPRETATION, interpretation )) < 0 )
			vips_error_exit( _( "bad interpretation %s" ), 
				interpretation );

		im->Type = i;
	}
	if( coding ) {
		int c;

		if( (c = vips_enum_from_nick( argv[0],
				VIPS_TYPE_CODING, coding )) < 0 )
			vips_error_exit( _( "bad coding %s" ), coding );

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

	if( vips__seek( im->fd, 0, SEEK_SET ) == (off_t) -1 )
		vips_error_exit( _( "could not seek on %s" ), im->filename );
	if( vips__write_header_bytes( im, header ) ||
		vips__write( im->fd, header, VIPS_SIZEOF_HEADER ) )
		vips_error_exit( _( "could not write to %s" ), im->filename );

	if( setext ) {
		char *xml;
		size_t size;

		if( !(xml = vips__file_read( stdin, "stdin", &size )) )
			vips_error_exit( "%s", _( "could not get ext data" ) );

		/* Strip trailing whitespace ... we can get stray \n at the 
		 * end, eg. "echo | vipsedit --setext fred.v".
		 */
		while( size > 0 && isspace( xml[size - 1] ) )
			size -= 1;

		if( vips__write_extension_block( im, xml, size ) )
			vips_error_exit( "%s", _( "could not set extension" ) );
		g_free( xml );
	}

	g_object_unref( im );

	g_option_context_free( context );

#ifdef G_OS_WIN32
	g_strfreev( argv ); 
#endif /*G_OS_WIN32*/

	vips_shutdown();

	return( 0 );
}

