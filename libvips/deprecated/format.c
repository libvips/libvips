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

#include <vips/vips.h>
#include <vips/internal.h>

/* To iterate over supported formats, we build a temp list of subclasses of 
 * VipsFormat, sort by priority, iterate, and free.
 */

static void *
format_add_class( VipsFormatClass *format, GSList **formats )
{
	if( !G_TYPE_IS_ABSTRACT( G_OBJECT_CLASS_TYPE( format ) ) )
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
 * vips_format_map: (skip)
 * @fn: function to apply to each #VipsFormatClass
 * @a: user data
 * @b: user data
 *
 * Apply a function to every %VipsFormatClass that VIPS knows about. Formats
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
	(void) vips_class_map_all( g_type_from_name( "VipsFormat" ), 
		(VipsClassMapFn) format_add_class, (void *) &formats );

	formats = g_slist_sort( formats, (GCompareFunc) format_compare );
	result = im_slist_map2( formats, fn, a, b );
	g_slist_free( formats );

	return( result );
}

/* Abstract base class for image formats.
 */

G_DEFINE_ABSTRACT_TYPE( VipsFormat, vips_format, VIPS_TYPE_OBJECT );

static void
vips_format_summary_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsFormatClass *class = VIPS_FORMAT_CLASS( object_class );

	VIPS_OBJECT_CLASS( vips_format_parent_class )->
		summary_class( object_class, buf );
	vips_buf_appends( buf, ", " );

	if( class->suffs ) {
		const char **p;

		vips_buf_appends( buf, "(" );
		for( p = class->suffs; *p; p++ ) {
			vips_buf_appendf( buf, "%s", *p );
			if( p[1] )
				vips_buf_appends( buf, ", " );
		}
		vips_buf_appends( buf, ") " );
	}

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

	object_class->nickname = "format";
	object_class->description = _( "VIPS file formats" );
	object_class->summary_class = vips_format_summary_class;

	/* Hide from UI.
	 */
	object_class->deprecated = TRUE;
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

static const char *vips_suffs[] = { ".v", ".vips", NULL };

int
im_isvips( const char *filename )
{
	unsigned char buf[4];

	if( im__get_bytes( filename, buf, 4 ) ) {
		if( buf[0] == 0x08 && buf[1] == 0xf2 &&
			buf[2] == 0xa6 && buf[3] == 0xb6 )
			/* SPARC-order VIPS image.
			 */
			return( 1 );
		else if( buf[3] == 0x08 && buf[2] == 0xf2 &&
			buf[1] == 0xa6 && buf[0] == 0xb6 )
			/* INTEL-order VIPS image.
			 */
			return( 1 );
	}

	return( 0 );
}

static int
file2vips( const char *filename, IMAGE *out )
{
	IMAGE *im;

	if( !(im = im_open_local( out, filename, "r" )) ||
		im_copy( im, out ) )
		return( -1 );

	return( 0 );
}

static VipsFormatFlags
vips_flags( const char *filename )
{
	VipsFormatFlags flags;
	unsigned char buf[4];

	flags = VIPS_FORMAT_PARTIAL;

	if( im__get_bytes( filename, buf, 4 ) &&
		buf[0] == 0x08 && 
		buf[1] == 0xf2 &&
		buf[2] == 0xa6 && 
		buf[3] == 0xb6 )
		flags |= VIPS_FORMAT_BIGENDIAN;

	return( flags );
}

/* Vips format adds no new members.
 */
typedef VipsFormat VipsFormatVips;
typedef VipsFormatClass VipsFormatVipsClass;

static int
vips_format_vips_save( VipsImage *image, const char *filename )
{
	return( vips_image_write_to_file( image, filename, NULL ) ); 
}

static void
vips_format_vips_class_init( VipsFormatVipsClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "vips";
	object_class->description = _( "VIPS" );

	format_class->priority = 200;
	format_class->is_a = im_isvips;
	format_class->header = file2vips;
	format_class->load = file2vips;
	format_class->save = vips_format_vips_save;
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
	extern GType vips_format_csv_get_type( void );
	extern GType vips_format_ppm_get_type( void );
	extern GType vips_format_analyze_get_type( void );
	extern GType vips_format_rad_get_type( void );

	vips_format_vips_get_type();
#ifdef HAVE_JPEG
	extern GType vips_format_jpeg_get_type( void );
	vips_format_jpeg_get_type();
#endif /*HAVE_JPEG*/
#ifdef HAVE_PNG
	extern GType vips_format_png_get_type( void );
	vips_format_png_get_type();
#endif /*HAVE_PNG*/
#ifdef HAVE_LIBWEBP
	extern GType vips_format_webp_get_type( void );
	vips_format_webp_get_type();
#endif /*HAVE_LIBWEBP*/
	vips_format_csv_get_type();
	vips_format_ppm_get_type();
	vips_format_analyze_get_type();
#ifdef HAVE_OPENEXR
	extern GType vips_format_exr_get_type( void );
	vips_format_exr_get_type();
#endif /*HAVE_OPENEXR*/
#ifdef HAVE_MATIO
	extern GType vips_format_mat_get_type( void );
	vips_format_mat_get_type();
#endif /*HAVE_MATIO*/
#ifdef HAVE_CFITSIO
	extern GType vips_format_fits_get_type( void );
	vips_format_fits_get_type();
#endif /*HAVE_CFITSIO*/
	vips_format_rad_get_type();
#ifdef HAVE_MAGICK
	extern GType vips_format_magick_get_type( void );
	vips_format_magick_get_type();
#endif /*HAVE_MAGICK*/
#ifdef HAVE_TIFF
	extern GType vips_format_tiff_get_type( void );
	vips_format_tiff_get_type();
#endif /*HAVE_TIFF*/
	extern GType vips_format_openslide_get_type( void );
	vips_format_openslide_get_type();
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
 * @filename: file to find a format for
 *
 * Searches for a format you could use to load a file.
 *
 * See also: vips_format_read(), vips_format_for_name().
 *
 * Returns: a format on success, %NULL on error
 */
VipsFormatClass *
vips_format_for_file( const char *filename )
{
	char name[FILENAME_MAX];
	char options[FILENAME_MAX];
	VipsFormatClass *format;

	/* Break any options off the name ... eg. "fred.tif:jpeg,tile" 
	 * etc.
	 */
	im_filename_split( filename, name, options );

	if( !im_existsf( "%s", name ) ) {
		im_error( "VipsFormat", _( "file \"%s\" not found" ), name );
		return( NULL );
	}

	if( !(format = (VipsFormatClass *) vips_format_map( 
		(VSListMap2Fn) format_for_file_sub, 
		(void *) filename, (void *) name )) ) {
		im_error( "VipsFormat", 
			_( "file \"%s\" not a known format" ), name );
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
 * @filename: name to find a format for
 *
 * Searches for a format you could use to save a file.
 *
 * See also: vips_format_write(), vips_format_for_file().
 *
 * Returns: a format on success, %NULL on error
 */
VipsFormatClass *
vips_format_for_name( const char *filename )
{
	VipsFormatClass *format;

	if( !(format = (VipsFormatClass *) vips_format_map( 
		(VSListMap2Fn) format_for_name_sub, 
		(void *) filename, NULL )) ) {
		im_error( "VipsFormat",
			_( "\"%s\" is not a supported image format." ), 
			filename );

		return( NULL );
	}

	return( format );
}

/**
 * vips_format_read:
 * @filename: file to load
 * @out: write the file to this image
 *
 * Searches for a format for this file, then loads the file into @out.
 *
 * See also: vips_format_write().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_format_read( const char *filename, IMAGE *out )
{
	VipsFormatClass *format;

	if( !(format = vips_format_for_file( filename )) || 
		format->load( filename, out ) )
		return( -1 );

	return( 0 );
}

/**
 * vips_format_write:
 * @in: image to write
 * @filename: file to write to
 *
 * Searches for a format for this name, then saves @im to it.
 *
 * See also: vips_format_read().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_format_write( IMAGE *in, const char *filename )
{
	VipsFormatClass *format;

	if( !(format = vips_format_for_name( filename )) || 
		format->save( in, filename ) ) 
		return( -1 );

	return( 0 );
}
