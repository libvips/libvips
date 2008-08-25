/* VIPS function dispatch tables for image format load/save.
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
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* List of loaded formats.
 */
static GSList *format_list = NULL;

static gint
format_compare( im_format_t *a, im_format_t *b )
{
        return( b->priority - a->priority );
}

/* Sort the format list after a change.
 */
static void
format_sort( void )
{
	format_list = g_slist_sort( format_list, 
		(GCompareFunc) format_compare );
}

/* Register/unregister formats.
 */
im_format_t *
im_format_register( 
	const char *name, const char *name_user, const char **suffs,
	im_format_is_a_fn is_a, im_format_header_fn header,
	im_format_load_fn load, im_format_save_fn save,
	im_format_flags_fn flags )
{
	im_format_t *format;

	if( !(format = IM_NEW( NULL, im_format_t )) )
		return( NULL );
	format->name = name;
	format->name_user = name_user;
	format->priority = 0;
	format->suffs = suffs; 
	format->is_a = is_a;
	format->header = header;
	format->load = load;
	format->save = save;
	format->flags = flags;

	/* Append, so we keep the ordering where possible.
	 */
	format_list = g_slist_append( format_list, format );
	format_sort();

	return( format );
}

void 
im_format_set_priority( im_format_t *format, int priority )
{
	g_assert( format );

	format->priority = priority;
	format_sort();
}

void 
im_format_unregister( im_format_t *format )
{
	format_list = g_slist_remove( format_list, format );
	IM_FREE( format );
}

/* Called on startup: register the base vips formats.
 */
void
im__format_init( void )
{
#ifdef HAVE_JPEG
	im__jpeg_register();
#endif /*HAVE_JPEG*/
#ifdef HAVE_PNG
	im__png_register();
#endif /*HAVE_PNG*/
	im__csv_register();
	im__ppm_register();
	im__analyze_register();
#ifdef HAVE_OPENEXR
	im__exr_register();
#endif /*HAVE_OPENEXR*/
#ifdef HAVE_MAGICK
	im__magick_register();
#endif /*HAVE_MAGICK*/
#ifdef HAVE_TIFF
	im__tiff_register();
#endif /*HAVE_TIFF*/
}

/* Map a function over all formats. 
 */
void *
im_format_map( VSListMap2Fn fn, void *a, void *b )
{
	return( im_slist_map2( format_list, fn, a, b ) );
}

/* Can this format open this file?
 */
static void *
format_for_file_sub( im_format_t *format, 
	const char *filename, const char *name )
{
	if( format->is_a ) {
		if( format->is_a( name ) ) 
			return( format );
	}
	else if( im_filename_suffix_match( name, format->suffs ) )
		return( format );

	return( NULL );
}

im_format_t *
im_format_for_file( const char *filename )
{
	char name[FILENAME_MAX];
	char options[FILENAME_MAX];
	im_format_t *format;

	/* Break any options off the name ... eg. "fred.tif:jpeg,tile" 
	 * etc.
	 */
	im_filename_split( filename, name, options );

	if( !im_existsf( "%s", name ) ) {
		im_error( "im_format_for_file", 
			_( "\"%s\" is not readable" ), name );
		return( NULL );
	}

	format = (im_format_t *) im_format_map( 
		(VSListMap2Fn) format_for_file_sub, 
		(void *) filename, (void *) name );

	if( !format ) {
		im_error( "im_format_for_file", 
			_( "\"%s\" is not in a supported format" ), name );
		return( NULL );
	}

	return( format );
}

/* Can we write this filename with this format? Ignore formats without a save
 * method.
 */
static void *
format_for_name_sub( im_format_t *format, 
	const char *filename, const char *name )
{
	if( format->save &&
		im_filename_suffix_match( name, format->suffs ) )
		return( format );

	return( NULL );
}

im_format_t *
im_format_for_name( const char *filename )
{
	char name[FILENAME_MAX];
	char options[FILENAME_MAX];

	/* Break any options off the name ... eg. "fred.tif:jpeg,tile" 
	 * etc.
	 */
	im_filename_split( filename, name, options );

	return( (im_format_t *) im_format_map( 
		(VSListMap2Fn) format_for_name_sub, 
		(void *) filename, (void *) name ) );
}

