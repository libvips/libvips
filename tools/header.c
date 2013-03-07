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
 * 27/2/13
 * 	- convert to vips8 API
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
print_error( void )
{
        fprintf( stderr, "%s: %s", g_get_prgname(), vips_error_buffer() );
	vips_error_clear();
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
		extra = vips_enum_nick( 
			VIPS_TYPE_CODING, g_value_get_int( value ) );
	else if( strcmp( field, "format" ) == 0 )
		extra = vips_enum_nick( 
			VIPS_TYPE_BAND_FORMAT, g_value_get_int( value ) );
	else if( strcmp( field, "interpretation" ) == 0 )
		extra = vips_enum_nick( 
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
print_header( VipsImage *im, gboolean many )
{
	if( !main_option_field ) {
		printf( "%s: ", im->filename );

		vips_object_print_summary( VIPS_OBJECT( im ) );

		if( main_option_all )
			(void) vips_image_map( im, print_field_fn, &many );
	}
	else if( strcmp( main_option_field, "getext" ) == 0 ) {
		if( vips__has_extension_block( im ) ) {
			void *buf;
			int size;

			if( !(buf = vips__read_extension_block( im, &size )) )
				return( -1 );
			printf( "%s", (char *) buf );
			g_free( buf );
		}
	}
	else if( strcmp( main_option_field, "Hist" ) == 0 ) 
		printf( "%s", vips_image_get_history( im ) );
	else {
		char *str;

		if( vips_image_get_as_string( im, main_option_field, &str ) )
			return( -1 );
		printf( "%s\n", str );
		g_free( str );
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

	if( vips_init( argv[0] ) )
	        vips_error_exit( "unable to start VIPS" );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

        context = g_option_context_new( _( "- print image header" ) );

	g_option_context_add_main_entries( context,
		main_option, GETTEXT_PACKAGE );
	g_option_context_add_group( context, vips_get_option_group() );

	if( !g_option_context_parse( context, &argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		vips_error_exit( "try \"%s --help\"", g_get_prgname() );
	}

	g_option_context_free( context );

	result = 0;

	for( i = 1; i < argc; i++ ) {
		VipsImage *im;

		if( !(im = vips_image_new_from_file( argv[i] )) ) {
			print_error();
			result = 1;
		}

		if( im && 
			print_header( im, argc > 2 ) ) {
			print_error();
			result = 1;
		}

		if( im )
			g_object_unref( im );
	}

	vips_shutdown();

	return( result );
}
