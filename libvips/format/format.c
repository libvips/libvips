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

/**
 * SECTION: format
 * @short_description: load and save in a variety of formats
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * VIPS has a simple system for representing image load and save operations in
 * a generic way.
 * You can ask for a loader for a certain file, select a saver based on a
 * filename, or register a new image file format. You can also call the
 * converters directly, if you like.
 *
 * Each format has a priority. Some loaders (such as the libMagick one) can
 * handle several formats. Priorities let you ensure that these generic
 * loaders are only used as a last resort. 
 *
 * Each format has a set of flags you can read which hint about the loader's
 * capabilities. See #VipsFormatFlags.
 *
 * VIPS comes with loaders for TIFF, JPEG, PNG, Analyze, PPM, OpenEXR, CSV,
 * RAW and one that wraps libMagick. 
 */

/* To iterate over supported formats, we build a temp list of subclasses of 
 * VipsFormat, sort by priority, iterate, and free.
 */

static void *
format_add_class( VipsFormatClass *format, GSList **formats )
{
	/* Append so we don't reverse the list of formats.
	 */
	*formats = g_slist_append( *formats, format );

	return( NULL );
}

static gint
format_compare( VipsFormatClass *a, VipsFormatClass *b )
{
        return( b->priority - a->priority );
}

/**
 * vips_format_map:
 * @fn: function to apply to each #VipsFormatClass
 * @a: user data
 * @b: user data
 *
 * Apply a function to every #VipsFormatClass that VIPS knows about. Formats
 * are presented to the function in priority order. 
 *
 * Like all VIPS map functions, if @fn returns %NULL, iteration continues. If
 * it returns non-%NULL, iteration terminates and that value is returned. The
 * map function returns %NULL if all calls return %NULL.
 *
 * See also: im_slist_map().
 *
 * Returns: the result of iteration
 */
void *
vips_format_map( VSListMap2Fn fn, void *a, void *b )
{
	GSList *formats;
	void *result;

	formats = NULL;
	(void) vips_class_map_concrete_all( g_type_from_name( "VipsFormat" ), 
		(VipsClassMap) format_add_class, (void *) &formats );

	formats = g_slist_sort( formats, (GCompareFunc) format_compare );
	result = im_slist_map2( formats, fn, a, b );
	g_slist_free( formats );

	return( result );
}

/* Abstract base class for image formats.
 */

G_DEFINE_ABSTRACT_TYPE( VipsFormat, vips_format, VIPS_TYPE_OBJECT );

static void
vips_format_print_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsFormatClass *class = VIPS_FORMAT_CLASS( object_class );
	const char **p;

	VIPS_OBJECT_CLASS( vips_format_parent_class )->
		print_class( object_class, buf );

	vips_buf_appends( buf, ", (" );
	for( p = class->suffs; *p; p++ ) {
		vips_buf_appendf( buf, "%s", *p );
		if( p[1] )
			vips_buf_appends( buf, ", " );
	}
	vips_buf_appends( buf, ") " );
	
	if( class->is_a )
		vips_buf_appends( buf, "is_a " );
	if( class->header )
		vips_buf_appends( buf, "header " );
	if( class->load )
		vips_buf_appends( buf, "load " );
	if( class->save )
		vips_buf_appends( buf, "save " );
	if( class->get_flags )
		vips_buf_appends( buf, "get_flags " );
}

static void
vips_format_class_init( VipsFormatClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->print_class = vips_format_print_class;
}

static void
vips_format_init( VipsFormat *object )
{
}

/**
 * vips_format_get_flags:
 * @format: format to test
 * @filename: file to test
 *
 * Get a set of flags for this file. 
 *
 * Returns: flags for this format and file
 */
VipsFormatFlags
vips_format_get_flags( VipsFormatClass *format, const char *filename )
{
	return( format->get_flags ? format->get_flags( filename ) : 0 );
}

/* VIPS format class.
 */

static const char *vips_suffs[] = { ".v", NULL };

static int
file2vips( const char *filename, IMAGE *out )
{
	IMAGE *im;

	if( !(im = im_open_local( out, filename, "r" )) ||
		im_copy( im, out ) )
		return( -1 );

	return( 0 );
}

static int
vips2file( IMAGE *im, const char *filename )
{
	IMAGE *out;

	if( !(out = im_open_local( im, filename, "w" )) ||
		im_copy( im, out ) )
		return( -1 );

	return( 0 );
}

static VipsFormatFlags
vips_flags( const char *filename )
{
	return( VIPS_FORMAT_PARTIAL );
}

/* Vips format adds no new members.
 */
typedef VipsFormat VipsFormatVips;
typedef VipsFormatClass VipsFormatVipsClass;

static void
vips_format_vips_class_init( VipsFormatVipsClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "vips";
	object_class->description = _( "VIPS" );

	format_class->is_a = im_isvips;
	format_class->header = file2vips;
	format_class->load = file2vips;
	format_class->save = vips2file;
	format_class->get_flags = vips_flags;
	format_class->suffs = vips_suffs;
}

static void
vips_format_vips_init( VipsFormatVips *object )
{
}

G_DEFINE_TYPE( VipsFormatVips, vips_format_vips, VIPS_TYPE_FORMAT );

/* Called on startup: register the base vips formats.
 */
void
im__format_init( void )
{
	extern GType vips_format_csv_get_type();
	extern GType vips_format_ppm_get_type();
	extern GType vips_format_analyze_get_type();
	extern GType vips_format_rad_get_type();

	vips_format_vips_get_type();
#ifdef HAVE_JPEG
	extern GType vips_format_jpeg_get_type();
	vips_format_jpeg_get_type();
#endif /*HAVE_JPEG*/
#ifdef HAVE_PNG
	extern GType vips_format_png_get_type();
	vips_format_png_get_type();
#endif /*HAVE_PNG*/
	vips_format_csv_get_type();
	vips_format_ppm_get_type();
	vips_format_analyze_get_type();
#ifdef HAVE_OPENEXR
	extern GType vips_format_exr_get_type();
	vips_format_exr_get_type();
#endif /*HAVE_OPENEXR*/
#ifdef HAVE_MATIO
	extern GType vips_format_mat_get_type();
	vips_format_mat_get_type();
#endif /*HAVE_MATIO*/
	vips_format_rad_get_type();
#ifdef HAVE_MAGICK
	extern GType vips_format_magick_get_type();
	vips_format_magick_get_type();
#endif /*HAVE_MAGICK*/
#ifdef HAVE_TIFF
	extern GType vips_format_tiff_get_type();
	vips_format_tiff_get_type();
#endif /*HAVE_TIFF*/
}

/* Can this format open this file?
 */
static void *
format_for_file_sub( VipsFormatClass *format, 
	const char *name, const char *filename )
{
	if( format->is_a ) {
		if( format->is_a( filename ) ) 
			return( format );
	}
	else if( im_filename_suffix_match( filename, format->suffs ) )
		return( format );

	return( NULL );
}

/**
 * vips_format_for_file:
 * @name: file to find a format for
 *
 * Searches for a format you could use to load a file.
 *
 * See also: vips_format_read(), vips_format_for_name().
 *
 * Returns: a format on success, %NULL on error
 */
VipsFormatClass *
vips_format_for_file( const char *name )
{
	char filename[FILENAME_MAX];
	char options[FILENAME_MAX];
	VipsFormatClass *format;

	/* Break any options off the name ... eg. "fred.tif:jpeg,tile" 
	 * etc.
	 */
	im_filename_split( name, filename, options );

	if( !im_existsf( "%s", filename ) ) {
		im_error( "format_for_file", 
			_( "file \"%s\" not found" ), filename );
		return( NULL );
	}

	if( !(format = (VipsFormatClass *) vips_format_map( 
		(VSListMap2Fn) format_for_file_sub, 
		(void *) name, (void *) filename )) ) {
		im_error( "format_for_file", 
			_( "file \"%s\" not a known format" ), filename );
		return( NULL );
	}

	return( format );
}

/* Can we write this filename with this format? Ignore formats without a save
 * method.
 */
static void *
format_for_name_sub( VipsFormatClass *format, const char *name )
{
	if( format->save &&
		im_filename_suffix_match( name, format->suffs ) )
		return( format );

	return( NULL );
}

/**
 * vips_format_for_name:
 * @name: name to find a format for
 *
 * Searches for a format you could use to save a file.
 *
 * See also: vips_format_write(), vips_format_for_file().
 *
 * Returns: a format on success, %NULL on error
 */
VipsFormatClass *
vips_format_for_name( const char *name )
{
	VipsFormatClass *format;

	if( !(format = (VipsFormatClass *) vips_format_map( 
		(VSListMap2Fn) format_for_name_sub, (void *) name, NULL )) ) {
		char suffix[FILENAME_MAX];

		im_filename_suffix( name, suffix );
		im_error( "vips_format_for_name",
			_( "\"%s\" is not a supported image format." ), 
			suffix );

		return( NULL );
	}

	return( format );
}

/**
 * vips_format_read:
 * @name: file to load
 * @out: write the file to this image
 *
 * Searches for a format for this file, then loads the file into @out.
 *
 * See also: vips_format_write().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_format_read( const char *name, IMAGE *out )
{
	VipsFormatClass *format;

	if( !(format = vips_format_for_file( name )) || 
		format->load( name, out ) )
		return( -1 );

	return( 0 );
}

/**
 * vips_format_write:
 * @im: image to write
 * @name: file to write to
 *
 * Searches for a format for this name, then saves @im to it.
 *
 * See also: vips_format_read().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_format_write( IMAGE *im, const char *name )
{
	VipsFormatClass *format;

	if( !(format = vips_format_for_name( name )) || 
		format->save( im, name ) ) 
		return( -1 );

	return( 0 );
}
