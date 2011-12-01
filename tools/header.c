/* @(#) Command; reads the header of a Vasari picture file.
 * @(#) Usage: header vasari_file
 * @(#) 
 *
 * Copyright: Birkbeck College, History of Art Dept, London, VASARI project.
 *
 * Author: Nicos Dessipris
 * Written on: 17/01/1990
 * Modified on : 17/04/1990, 2/6/93 K.Martinez
 * 16/6/93 JC
 *	- now calls im_mmapin instead of bizzare bogosity
 * 1/6/95 JC
 *	- extra field argument for testing particular bits of the header
 * 29/10/98 JC
 *	- now uses im_open()
 * 24/5/01 JC
 *	- uses im_tiff2vips_header() etc., for speed
 * 7/5/03 JC
 *	- uses im_open_header()
 * 1/8/05
 * 	- uses new header API, for great smallness
 * 4/8/05
 * 	- back to plain im_open() now that's lazy enough for us
 * 9/9/05
 * 	- display meta fields in save format, if possible
 * 20/9/05 
 * 	- new field name "getext" reads extension block
 * 24/8/06
 *	- use GOption, loop over args
 * 4/1/07
 *	- use im_history_get()
 * 29/2/08
 * 	- don't stop on error
 * 23/7/09
 * 	- ... but do return an error code if anything failed
 * 6/11/09
 * 	- added im_history_get(), im_getexp(), im_printdesc() as wrapped
 * 	  functions, so "header" is now obsolete
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
#include <locale.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

static char *main_option_field = NULL;
static gboolean main_option_all = FALSE;

static GOptionEntry main_option[] = {
	{ "all", 'a', 0, G_OPTION_ARG_NONE, &main_option_all, 
		N_( "show all fields" ), NULL },
	{ "field", 'f', 0, G_OPTION_ARG_STRING, &main_option_field, 
		N_( "print value of FIELD (\"getext\" reads extension block, "
			"\"Hist\" reads image history)" ),
		"FIELD" },
	{ NULL }
};

/* A non-fatal error. Print the vips error buffer and continue.
 */
static void
print_error( const char *fmt, ... )
{
	va_list ap;

        va_start( ap, fmt );
        vfprintf( stderr, fmt, ap );
        va_end( ap );
        fprintf( stderr, "\n%s", im_error_buffer() );
	im_error_clear();
}

static void *
print_field_fn( VipsImage *image, const char *field, GValue *value, void *a )
{
	gboolean *many = (gboolean *) a;
	const char *extra;
	char *str_value;

	/* Look for known enums and decode them.
	 */
	extra = NULL;
	if( strcmp( field, "coding" ) == 0 )
		extra = VIPS_ENUM_NICK( 
			VIPS_TYPE_CODING, g_value_get_int( value ) );
	else if( strcmp( field, "format" ) == 0 )
		extra = VIPS_ENUM_NICK( 
			VIPS_TYPE_BAND_FORMAT, g_value_get_int( value ) );
	else if( strcmp( field, "interpretation" ) == 0 )
		extra = VIPS_ENUM_NICK( 
			VIPS_TYPE_INTERPRETATION, g_value_get_int( value ) );

	if( *many ) 
		printf( "%s: ", image->filename );

	str_value = g_strdup_value_contents( value );
	printf( "%s: %s", field, str_value );
	g_free( str_value );

	if( extra )
		printf( " - %s", extra );

	printf( "\n" );

	return( NULL );
}

/* Print header, or parts of header.
 */
static int
print_header( IMAGE *im, gboolean many )
{
	if( !main_option_field ) {
		printf( "%s: ", im->filename );

		printf( ngettext( 
			"%dx%d %s, %d band, %s", 
			"%dx%d %s, %d bands, %s", 
			vips_image_get_bands( im ) ),
			vips_image_get_width( im ),
			vips_image_get_height( im ),
			VIPS_ENUM_NICK( VIPS_TYPE_BAND_FORMAT, 
				vips_image_get_format( im ) ),
			vips_image_get_bands( im ),
			VIPS_ENUM_NICK( VIPS_TYPE_INTERPRETATION, 
				vips_image_get_interpretation( im ) ) );

		if( im->magic == VIPS_MAGIC_SPARC )
			printf( ", sparc" );
		else if( im->magic == VIPS_MAGIC_INTEL )
			printf( ", intel" );

		printf( "\n" );

		if( main_option_all )
			(void) vips_image_map( im, print_field_fn, &many );
	}
	else if( strcmp( main_option_field, "getext" ) == 0 ) {
		if( im__has_extension_block( im ) ) {
			void *buf;
			int size;

			if( !(buf = im__read_extension_block( im, &size )) )
				return( -1 );
			printf( "%s", (char *) buf );
			im_free( buf );
		}
	}
	else if( strcmp( main_option_field, "Hist" ) == 0 ) 
		printf( "%s", im_history_get( im ) );
	else {
		GValue value = { 0 };
		GType type;

		if( im_header_get( im, main_option_field, &value ) )
			return( -1 );

		/* Display the save form, if there is one. This way we display
		 * something useful for ICC profiles, xml fields, etc.
		 */
		type = G_VALUE_TYPE( &value );
		if( g_value_type_transformable( type, IM_TYPE_SAVE_STRING ) ) {
			GValue save_value = { 0 };

			g_value_init( &save_value, IM_TYPE_SAVE_STRING );
			if( !g_value_transform( &value, &save_value ) ) 
				return( -1 );
			printf( "%s\n", im_save_string_get( &save_value ) );
			g_value_unset( &save_value );
		}
		else {
			char *str_value;

			str_value = g_strdup_value_contents( &value );
			printf( "%s\n", str_value );
			g_free( str_value );
		}

		g_value_unset( &value );
	}

	return( 0 );
}

int
main( int argc, char *argv[] )
{
	GOptionContext *context;
	GError *error = NULL;
	int i;
	int result;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

        context = g_option_context_new( _( "- print image header" ) );

	g_option_context_add_main_entries( context,
		main_option, GETTEXT_PACKAGE );
	g_option_context_add_group( context, im_get_option_group() );

	if( !g_option_context_parse( context, &argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		error_exit( "try \"%s --help\"", g_get_prgname() );
	}

	g_option_context_free( context );

	result = 0;

	for( i = 1; i < argc; i++ ) {
		IMAGE *im;

		if( !(im = im_open( argv[i], "r" )) ) {
			print_error( "%s: unable to open", argv[i] );
			result = 1;
		}

		if( im && 
			print_header( im, argc > 2 ) ) {
			print_error( "%s: unable to print header", argv[i] );
			result = 1;
		}

		if( im )
			im_close( im );
	}

	vips_shutdown();

	return( result );
}
