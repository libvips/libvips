/* foreign file formats base class
 *
 * 7/2/12
 * 	- add support for sequential reads
 * 18/6/12
 * 	- flatten alpha with vips_flatten()
 * 28/5/13
 * 	- auto rshift down to 8 bits during save
 * 19/1/14
 * 	- pack and unpack rad to scrgb
 * 18/8/14
 * 	- fix conversion to 16-bit RGB, thanks John
 * 18/6/15
 * 	- forward progress signals from load
 * 23/5/16
 * 	- remove max-alpha stuff, this is now automatic
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

/*
 */
#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pforeign.h"

/**
 * SECTION: foreign
 * @short_description: load and save images in a variety of formats
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * This set of operations load and save images in a variety of formats. 
 *
 * The operations share a base class that offers a simple way to search for a
 * subclass of #VipsForeign which can load a certain file (see
 * vips_foreign_find_load()) or buffer (see vips_foreign_find_load_buffer()), 
 * or which could be used to save an image to a
 * certain file type (see vips_foreign_find_save() and
 * vips_foreign_find_save_buffer()). You can then run these
 * operations using vips_call() and friends to perform the load or save.
 *
 * vips_image_write_to_file() and vips_image_new_from_file() and friends use
 * these functions to automate file load and save. 
 *
 * You can also invoke the operations directly, for example:
 *
 * |[
 * vips_tiffsave (my_image, "frank.anything", 
 *     "compression", VIPS_FOREIGN_TIFF_COMPRESSION_JPEG,
 *     NULL);
 * ]|
 *
 * To add support for a new file format to vips, simply define a new subclass
 * of #VipsForeignLoad or #VipsForeignSave. 
 *
 * If you define a new operation which is a subclass of #VipsForeign, support 
 * for it automatically appears in all VIPS user-interfaces. It will also be
 * transparently supported by vips_image_new_from_file() and friends.
 *
 * VIPS comes with VipsForeign for TIFF, JPEG, PNG, Analyze, PPM, OpenEXR, CSV,
 * Matlab, Radiance, RAW, FITS, WebP, SVG, PDF, GIF and VIPS. It also includes 
 * import filters which can load with libMagick and with OpenSlide. 
 *
 * ## Writing a new loader
 *
 * Add a new loader to VIPS by subclassing #VipsForeignLoad. Subclasses need to 
 * implement at least @header().
 *
 * @header() must set at least the header fields of @out. @load(), if defined,
 * must load the pixels to @real.
 *
 * The suffix list is used to select a format to save a file in, and to pick a
 * loader if you don't define is_a().
 *
 * You should also define @nickname and @description in #VipsObject. 
 *
 * As a complete example, here's code for a PNG loader, minus the actual
 * calls to libpng.
 *
 * |[
 * typedef struct _VipsForeignLoadPng {
 *   VipsForeignLoad parent_object;
 * 
 *   char *filename; 
 * } VipsForeignLoadPng;
 * 
 * typedef VipsForeignLoadClass VipsForeignLoadPngClass;
 * 
 * G_DEFINE_TYPE( VipsForeignLoadPng, vips_foreign_load_png, 
 *   VIPS_TYPE_FOREIGN_LOAD );
 * 
 * static VipsForeignFlags
 * vips_foreign_load_png_get_flags_filename( const char *filename )
 * {
 *   VipsForeignFlags flags;
 * 
 *   flags = 0;
 *   if( vips__png_isinterlaced( filename ) )
 *   	flags = VIPS_FOREIGN_PARTIAL;
 *   else
 *   	flags = VIPS_FOREIGN_SEQUENTIAL;
 * 
 *   return( flags );
 * }
 * 
 * static VipsForeignFlags
 * vips_foreign_load_png_get_flags( VipsForeignLoad *load )
 * {
 *   VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;
 * 
 *   return( vips_foreign_load_png_get_flags_filename( png->filename ) );
 * }
 * 
 * static int
 * vips_foreign_load_png_header( VipsForeignLoad *load )
 * {
 *   VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;
 * 
 *   if( vips__png_header( png->filename, load->out ) )
 *   	return( -1 );
 * 
 *   return( 0 );
 * }
 * 
 * static int
 * vips_foreign_load_png_load( VipsForeignLoad *load )
 * {
 *   VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;
 * 
 *   if( vips__png_read( png->filename, load->real ) )
 *   	return( -1 );
 * 
 *   return( 0 );
 * }
 * 
 * static void
 * vips_foreign_load_png_class_init( VipsForeignLoadPngClass *class )
 * {
 *   GObjectClass *gobject_class = G_OBJECT_CLASS( class );
 *   VipsObjectClass *object_class = (VipsObjectClass *) class;
 *   VipsForeignClass *foreign_class = (VipsForeignClass *) class;
 *   VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;
 * 
 *   gobject_class->set_property = vips_object_set_property;
 *   gobject_class->get_property = vips_object_get_property;
 * 
 *   object_class->nickname = "pngload";
 *   object_class->description = _( "load png from file" );
 * 
 *   foreign_class->suffs = vips__png_suffs;
 * 
 *   load_class->is_a = vips__png_ispng;
 *   load_class->get_flags_filename = 
 *   	vips_foreign_load_png_get_flags_filename;
 *   load_class->get_flags = vips_foreign_load_png_get_flags;
 *   load_class->header = vips_foreign_load_png_header;
 *   load_class->load = vips_foreign_load_png_load;
 * 
 *   VIPS_ARG_STRING( class, "filename", 1, 
 *   	_( "Filename" ),
 *   	_( "Filename to load from" ),
 *   	VIPS_ARGUMENT_REQUIRED_INPUT, 
 *   	G_STRUCT_OFFSET( VipsForeignLoadPng, filename ),
 *   	NULL );
 * }
 * 
 * static void
 * vips_foreign_load_png_init( VipsForeignLoadPng *png )
 * {
 * }
 * ]|
 * 
 * ## Writing a new saver
 *
 * Call your saver in the class' @build() method after chaining up. The
 * prepared image should be ready for you to save in @ready.  
 *
 * As a complete example, here's the code for the CSV saver, minus the calls
 * to the actual save routines.
 *
 * |[
 * typedef struct _VipsForeignSaveCsv {
 *   VipsForeignSave parent_object;
 * 
 *   char *filename; 
 *   const char *separator;
 * } VipsForeignSaveCsv;
 * 
 * typedef VipsForeignSaveClass VipsForeignSaveCsvClass;
 * 
 * G_DEFINE_TYPE( VipsForeignSaveCsv, vips_foreign_save_csv, 
 *   VIPS_TYPE_FOREIGN_SAVE );
 * 
 * static int
 * vips_foreign_save_csv_build( VipsObject *object )
 * {
 *   VipsForeignSave *save = (VipsForeignSave *) object;
 *   VipsForeignSaveCsv *csv = (VipsForeignSaveCsv *) object;
 * 
 *   if( VIPS_OBJECT_CLASS( vips_foreign_save_csv_parent_class )->
 *   	build( object ) )
 *   	return( -1 );
 * 
 *   if( vips__csv_write( save->ready, csv->filename, csv->separator ) )
 *   	return( -1 );
 * 
 *   return( 0 );
 * }
 * 
 * static void
 * vips_foreign_save_csv_class_init( VipsForeignSaveCsvClass *class )
 * {
 *   GObjectClass *gobject_class = G_OBJECT_CLASS( class );
 *   VipsObjectClass *object_class = (VipsObjectClass *) class;
 *   VipsForeignClass *foreign_class = (VipsForeignClass *) class;
 *   VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;
 * 
 *   gobject_class->set_property = vips_object_set_property;
 *   gobject_class->get_property = vips_object_get_property;
 * 
 *   object_class->nickname = "csvsave";
 *   object_class->description = _( "save image to csv file" );
 *   object_class->build = vips_foreign_save_csv_build;
 * 
 *   foreign_class->suffs = vips__foreign_csv_suffs;
 * 
 *   save_class->saveable = VIPS_SAVEABLE_MONO;
 *   // no need to define ->format_table, we don't want the input 
 *   // cast for us
 * 
 *   VIPS_ARG_STRING( class, "filename", 1, 
 *   	_( "Filename" ),
 *   	_( "Filename to save to" ),
 *   	VIPS_ARGUMENT_REQUIRED_INPUT, 
 *   	G_STRUCT_OFFSET( VipsForeignSaveCsv, filename ),
 *   	NULL );
 * 
 *   VIPS_ARG_STRING( class, "separator", 13, 
 *   	_( "Separator" ), 
 *   	_( "Separator characters" ),
 *   	VIPS_ARGUMENT_OPTIONAL_INPUT,
 *   	G_STRUCT_OFFSET( VipsForeignSaveCsv, separator ),
 *   	"\t" ); 
 * }
 * 
 * static void
 * vips_foreign_save_csv_init( VipsForeignSaveCsv *csv )
 * {
 *   csv->separator = g_strdup( "\t" );
 * }
 * ]|
 */

/* Use this to link images to the load operation that made them. 
 */
static GQuark vips__foreign_load_operation = 0; 

/**
 * VipsForeignFlags: 
 * @VIPS_FOREIGN_NONE: no flags set
 * @VIPS_FOREIGN_PARTIAL: the image may be read lazilly
 * @VIPS_FOREIGN_BIGENDIAN: image pixels are most-significant byte first
 * @VIPS_FOREIGN_SEQUENTIAL: top-to-bottom lazy reading
 *
 * Some hints about the image loader.
 *
 * #VIPS_FOREIGN_PARTIAL means that the image can be read directly from the
 * file without needing to be unpacked to a temporary image first. 
 *
 * #VIPS_FOREIGN_SEQUENTIAL means that the loader supports lazy reading, but
 * only top-to-bottom (sequential) access. Formats like PNG can read sets of
 * scanlines, for example, but only in order. 
 *
 * If neither PARTIAL or SEQUENTIAL is set, the loader only supports whole
 * image read. Setting both PARTIAL and SEQUENTIAL is an error.
 *
 * #VIPS_FOREIGN_BIGENDIAN means that image pixels are most-significant byte
 * first. Depending on the native byte order of the host machine, you may
 * need to swap bytes. See vips_copy().
 */

G_DEFINE_ABSTRACT_TYPE( VipsForeign, vips_foreign, VIPS_TYPE_OPERATION );

static void
vips_foreign_summary_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsForeignClass *class = VIPS_FOREIGN_CLASS( object_class );

	VIPS_OBJECT_CLASS( vips_foreign_parent_class )->
		summary_class( object_class, buf );

	if( class->suffs ) {
		const char **p;

		vips_buf_appends( buf, " (" );
		for( p = class->suffs; *p; p++ ) {
			vips_buf_appendf( buf, "%s", *p );
			if( p[1] )
				vips_buf_appends( buf, ", " );
		}
		vips_buf_appends( buf, ")" );
	}

	vips_buf_appendf( buf, ", priority=%d", class->priority );

}

static void
vips_foreign_class_init( VipsForeignClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "foreign";
	object_class->description = _( "load and save image files" );
	object_class->summary_class = vips_foreign_summary_class;
}

static void
vips_foreign_init( VipsForeign *object )
{
}

/* To iterate over supported files we build a temp list of subclasses of 
 * VipsForeign, sort by priority, iterate, and free.
 */

static void *
file_add_class( VipsForeignClass *class, GSList **files )
{
	/* Append so we don't reverse the list of files. Sort will not reorder
	 * items of equal priority. 
	 */
	*files = g_slist_append( *files, class );

	return( NULL );
}

static gint
file_compare( VipsForeignClass *a, VipsForeignClass *b )
{
        return( b->priority - a->priority );
}

/**
 * vips_foreign_map:
 * @base: base class to search below (eg. "VipsForeignLoad")
 * @fn: (scope call): function to apply to each #VipsForeignClass
 * @a: user data
 * @b: user data
 *
 * Apply a function to every #VipsForeignClass that VIPS knows about. Foreigns
 * are presented to the function in priority order. 
 *
 * Like all VIPS map functions, if @fn returns %NULL, iteration continues. If
 * it returns non-%NULL, iteration terminates and that value is returned. The
 * map function returns %NULL if all calls return %NULL.
 *
 * See also: vips_slist_map().
 *
 * Returns: (transfer none): the result of iteration
 */
void *
vips_foreign_map( const char *base, VipsSListMap2Fn fn, void *a, void *b )
{
	GSList *files;
	void *result;

	files = NULL;
	(void) vips_class_map_all( g_type_from_name( base ), 
		(VipsClassMapFn) file_add_class, (void *) &files );

	files = g_slist_sort( files, (GCompareFunc) file_compare );
	result = vips_slist_map2( files, fn, a, b );
	g_slist_free( files );

	return( result );
}

/* Abstract base class for image load.
 */

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoad, vips_foreign_load, VIPS_TYPE_FOREIGN );

static void
vips_foreign_load_dispose( GObject *gobject )
{
	VipsForeignLoad *load = VIPS_FOREIGN_LOAD( gobject );

	VIPS_UNREF( load->real );

	G_OBJECT_CLASS( vips_foreign_load_parent_class )->dispose( gobject );
}

static void
vips_foreign_load_summary_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsForeignLoadClass *class = VIPS_FOREIGN_LOAD_CLASS( object_class );

	VIPS_OBJECT_CLASS( vips_foreign_load_parent_class )->
		summary_class( object_class, buf );

	if( !G_TYPE_IS_ABSTRACT( G_TYPE_FROM_CLASS( class ) ) ) {
		if( class->is_a )
			vips_buf_appends( buf, ", is_a" );
		if( class->is_a_buffer )
			vips_buf_appends( buf, ", is_a_buffer" );
		if( class->get_flags )
			vips_buf_appends( buf, ", get_flags" );
		if( class->get_flags_filename )
			vips_buf_appends( buf, ", get_flags_filename" );
		if( class->header )
			vips_buf_appends( buf, ", header" );
		if( class->load )
			vips_buf_appends( buf, ", load" );

		/* You can omit ->load(), you must not omit ->header().
		 */
		g_assert( class->header );
	}
}

/* Can this VipsForeign open this file?
 */
static void *
vips_foreign_find_load_sub( VipsForeignLoadClass *load_class, 
	const char *filename )
{
	VipsForeignClass *class = VIPS_FOREIGN_CLASS( load_class );

#ifdef DEBUG
	printf( "vips_foreign_find_load_sub: %s\n", 
		VIPS_OBJECT_CLASS( class )->nickname );
#endif /*DEBUG*/

	if( load_class->is_a ) {
		if( load_class->is_a( filename ) ) 
			return( load_class );

#ifdef DEBUG
		printf( "vips_foreign_find_load_sub: is_a failed\n" ); 
#endif /*DEBUG*/
	}
	else if( class->suffs && 
		vips_filename_suffix_match( filename, class->suffs ) )
		return( load_class );
	else {
#ifdef DEBUG
		printf( "vips_foreign_find_load_sub: suffix match failed\n" ); 
#endif /*DEBUG*/
	}

	return( NULL );
}

/**
 * vips_foreign_find_load:
 * @filename: file to find a loader for
 *
 * Searches for an operation you could use to load @filename. Any trailing
 * options on @filename are stripped and ignored. 
 *
 * See also: vips_foreign_find_load_buffer(), vips_image_new_from_file().
 *
 * Returns: the name of an operation on success, %NULL on error
 */
const char *
vips_foreign_find_load( const char *name )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	VipsForeignLoadClass *load_class;

	vips__filename_split8( name, filename, option_string );

	if( !vips_existsf( "%s", filename ) ) {
		vips_error( "VipsForeignLoad", 
			_( "file \"%s\" not found" ), name );
		return( NULL );
	}

	if( !(load_class = (VipsForeignLoadClass *) vips_foreign_map( 
		"VipsForeignLoad",
		(VipsSListMap2Fn) vips_foreign_find_load_sub, 
		(void *) filename, NULL )) ) {
		vips_error( "VipsForeignLoad", 
			_( "\"%s\" is not a known file format" ), name );
		return( NULL );
	}

#ifdef DEBUG
	printf( "vips_foreign_find_load: selected %s\n", 
		VIPS_OBJECT_CLASS( load_class )->nickname );
#endif /*DEBUG*/

	return( G_OBJECT_CLASS_NAME( load_class ) );
}

/* Kept for compat with earlier version of the vip8 API. Use
 * vips_image_new_from_file() now. 
 */

int
vips_foreign_load( const char *name, VipsImage **out, ... )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	int result;

	vips__filename_split8( name, filename, option_string );
	if( !(operation_name = vips_foreign_find_load( filename )) )
		return( -1 );

	va_start( ap, out );
	result = vips_call_split_option_string( operation_name, option_string, 
		ap, filename, out );
	va_end( ap );

	return( result );
}

/* Can this VipsForeign open this buffer?
 */
static void *
vips_foreign_find_load_buffer_sub( VipsForeignLoadClass *load_class, 
	const void **buf, size_t *len )
{
	if( load_class->is_a_buffer &&
		load_class->is_a_buffer( *buf, *len ) ) 
		return( load_class );

	return( NULL );
}

/**
 * vips_foreign_find_load_buffer:
 * @data: (array length=size) (element-type guint8) (transfer none): start of 
 * memory buffer
 * @size: number of bytes in @data
 *
 * Searches for an operation you could use to load a memory buffer. To see the
 * range of buffer loaders supported by your vips, try something like:
 * 
 * 	vips -l | grep load_buffer
 *
 * See also: vips_image_new_from_buffer().
 *
 * Returns: (transfer none): the name of an operation on success, %NULL on 
 * error.
 */
const char *
vips_foreign_find_load_buffer( const void *data, size_t size )
{
	VipsForeignLoadClass *load_class;

	if( !(load_class = (VipsForeignLoadClass *) vips_foreign_map( 
		"VipsForeignLoad",
		(VipsSListMap2Fn) vips_foreign_find_load_buffer_sub, 
		&data, &size )) ) {
		vips_error( "VipsForeignLoad", 
			"%s", _( "buffer is not in a known format" ) ); 
		return( NULL );
	}

	return( G_OBJECT_CLASS_NAME( load_class ) );
}

/**
 * vips_foreign_is_a:
 * @loader: name of loader to use for test
 * @filename: file to test
 *
 * Return %TRUE if @filename can be loaded by @loader. @loader is something
 * like "tiffload" or "VipsForeignLoadTiff".
 *
 * Returns: %TRUE if @filename can be loaded by @loader.
 */
gboolean 
vips_foreign_is_a( const char *loader, const char *filename )
{
	const VipsObjectClass *class;
	VipsForeignLoadClass *load_class;

	if( !(class = vips_class_find( "VipsForeignLoad", loader )) ) 
		return( FALSE );
	load_class = VIPS_FOREIGN_LOAD_CLASS( class );
	if( load_class->is_a &&
		load_class->is_a( filename ) ) 
		return( TRUE );

	return( FALSE );
}

/**
 * vips_foreign_is_a_buffer:
 * @loader: name of loader to use for test
 * @data: pointer to the buffer to test
 * @size: size of the buffer to test
 *
 * Return %TRUE if @data can be loaded by @loader. @loader is something
 * like "tiffload_buffer" or "VipsForeignLoadTiffBuffer".
 *
 * Returns: %TRUE if @data can be loaded by @loader.
 */
gboolean
vips_foreign_is_a_buffer( const char *loader, const void *data, size_t size )
{
	const VipsObjectClass *class;
	VipsForeignLoadClass *load_class;

	if( !(class = vips_class_find( "VipsForeignLoad", loader )) )
		return( FALSE );
	load_class = VIPS_FOREIGN_LOAD_CLASS( class );
	if( load_class->is_a_buffer &&
		load_class->is_a_buffer( data, size ) )
		return( TRUE );

	return( FALSE );
}

/**
 * vips_foreign_flags:
 * @loader: name of loader to use for test
 * @filename: file to test
 *
 * Return the flags for @filename using @loader. 
 * @loader is something like "tiffload" or "VipsForeignLoadTiff".
 *
 * Returns: the flags for @filename.
 */
VipsForeignFlags 
vips_foreign_flags( const char *loader, const char *filename )
{
	const VipsObjectClass *class;

	if( (class = vips_class_find( "VipsForeignLoad", loader )) ) {
		VipsForeignLoadClass *load_class = 
			VIPS_FOREIGN_LOAD_CLASS( class );

		if( load_class->get_flags_filename ) 
			return( load_class->get_flags_filename( filename ) );
	}

	return( 0 );
}

static VipsObject *
vips_foreign_load_new_from_string( const char *string )
{
	const char *file_op;
	GType type;
	VipsForeignLoad *load;

	if( !(file_op = vips_foreign_find_load( string )) )
		return( NULL );
	type = g_type_from_name( file_op );
	g_assert( type ); 

	load = VIPS_FOREIGN_LOAD( g_object_new( type, NULL ) );
	g_object_set( load,
		"filename", string,
		NULL );

	return( VIPS_OBJECT( load ) );
}

static VipsImage *
vips_foreign_load_temp( VipsForeignLoad *load )
{
	const guint64 disc_threshold = vips_get_disc_threshold();
	const guint64 image_size = VIPS_IMAGE_SIZEOF_IMAGE( load->out );

	/* If this is a partial operation, we can open directly.
	 */
	if( load->flags & VIPS_FOREIGN_PARTIAL ) {
#ifdef DEBUG
		printf( "vips_foreign_load_temp: partial temp\n" );
#endif /*DEBUG*/

		return( vips_image_new() );
	}

	/* If it can do sequential access and it's been requested, we can open
	 * directly.
	 */
	if( (load->flags & VIPS_FOREIGN_SEQUENTIAL) && 
		load->access != VIPS_ACCESS_RANDOM ) {
#ifdef DEBUG
		printf( "vips_foreign_load_temp: partial sequential temp\n" );
#endif /*DEBUG*/

		return( vips_image_new() );
	}

	/* We open via disc if:
	 * - 'disc' is set
	 * - the uncompressed image will be larger than 
	 *   vips_get_disc_threshold()
	 */
	if( load->disc && 
		image_size > disc_threshold ) {
#ifdef DEBUG
		printf( "vips_foreign_load_temp: disc temp\n" );
#endif /*DEBUG*/

		return( vips_image_new_temp_file( "%s.v" ) );
	}

#ifdef DEBUG
	printf( "vips_foreign_load_temp: memory temp\n" );
#endif /*DEBUG*/

	/* Otherwise, fall back to a memory buffer.
	 */
	return( vips_image_new_memory() );
}

/* Check two images for compatibility: their geometries need to match.
 */
static gboolean
vips_foreign_load_iscompat( VipsImage *a, VipsImage *b )
{
	if( a->Xsize != b->Xsize ||
		a->Ysize != b->Ysize ||
		a->Bands != b->Bands ||
		a->Coding != b->Coding ||
		a->BandFmt != b->BandFmt ) {
		vips_error( "VipsForeignLoad",
			"%s", _( "images do not match" ) ); 
		return( FALSE );
	}

	return( TRUE );
}

/* Our start function ... do the lazy open, if necessary, and return a region
 * on the new image.
 */
static void *
vips_foreign_load_start( VipsImage *out, void *a, void *b )
{
	VipsForeignLoad *load = VIPS_FOREIGN_LOAD( b );
	VipsForeignLoadClass *class = VIPS_FOREIGN_LOAD_GET_CLASS( load );

	if( !load->real ) {
		if( !(load->real = vips_foreign_load_temp( load )) )
			return( NULL );

#ifdef DEBUG
		printf( "vips_foreign_load_start: triggering ->load()\n" );
#endif /*DEBUG*/

		/* Read the image in. This may involve a long computation and
		 * will finish with load->real holding the decompressed image. 
		 *
		 * We want our caller to be able to see this computation on
		 * @out, so eval signals on ->real need to appear on ->out.
		 */
		load->real->progress_signal = load->out;

		/* Note the load object on the image. Loaders can use 
		 * this to signal invalidate if they hit a load error. See
		 * vips_foreign_load_invalidate() below.
		 */
		g_object_set_qdata( G_OBJECT( load->real ), 
			vips__foreign_load_operation, load ); 

		if( class->load( load ) ||
			vips_image_pio_input( load->real ) ) 
			return( NULL );

		/* ->header() read the header into @out, load has read the
		 * image into @real. They must match exactly in size, bands,
		 * format and coding for the copy to work.  
		 *
		 * Some versions of ImageMagick give different results between
		 * Ping and Load for some formats, for example.
		 */
		if( !vips_foreign_load_iscompat( load->real, out ) )
			return( NULL );

		/* We have to tell vips that out depends on real. We've set
		 * the demand hint below, but not given an input there.
		 */
		vips_image_pipelinev( load->out, load->out->dhint, 
			load->real, NULL );

	}

	return( vips_region_new( load->real ) );
}

/* Just pointer-copy.
 */
static int
vips_foreign_load_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;

        VipsRect *r = &or->valid;

        /* Ask for input we need.
         */
        if( vips_region_prepare( ir, r ) )
                return( -1 );

        /* Attach output region to that.
         */
        if( vips_region_region( or, ir, r, r->left, r->top ) )
                return( -1 );

        return( 0 );
}

static int
vips_foreign_load_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignLoad *load = VIPS_FOREIGN_LOAD( object );
	VipsForeignLoadClass *fclass = VIPS_FOREIGN_LOAD_GET_CLASS( object );

	VipsForeignFlags flags;

#ifdef DEBUG
	printf( "vips_foreign_load_build:\n" );
#endif /*DEBUG*/

	flags = 0;
	if( fclass->get_flags )
		flags |= fclass->get_flags( load );

	if( (flags & VIPS_FOREIGN_PARTIAL) &&
		(flags & VIPS_FOREIGN_SEQUENTIAL) ) {
		g_warning( "%s", 
			_( "VIPS_FOREIGN_PARTIAL and VIPS_FOREIGN_SEQUENTIAL "
				"both set -- using SEQUENTIAL" ) );
		flags ^= VIPS_FOREIGN_PARTIAL;
	}

	g_object_set( load, "flags", flags, NULL );

	/* If the loader can do sequential mode and sequential has been
	 * requested, we need to block caching.
	 */
	if( (load->flags & VIPS_FOREIGN_SEQUENTIAL) && 
		load->access != VIPS_ACCESS_RANDOM ) 
		load->nocache = TRUE;

	if( VIPS_OBJECT_CLASS( vips_foreign_load_parent_class )->
		build( object ) )
		return( -1 );

	if( load->sequential ) 
		g_warning( "%s", 
			_( "ignoring deprecated \"sequential\" mode -- "
				"please use \"access\" instead" ) ); 

	g_object_set( object, "out", vips_image_new(), NULL ); 

	vips_image_set_string( load->out, 
		VIPS_META_LOADER, class->nickname );

#ifdef DEBUG
	printf( "vips_foreign_load_build: triggering ->header()\n" );
#endif /*DEBUG*/

	/* Read the header into @out.
	 */
	if( fclass->header &&
		fclass->header( load ) ) 
		return( -1 );

	/* If there's no ->load() method then the header read has done
	 * everything. Otherwise, it's just set fields and we must also
	 * load pixels.
	 *
	 * Delay the load until the first pixel is requested by doing the work
	 * in the start function of the copy.
	 */
	if( fclass->load ) {
#ifdef DEBUG
		printf( "vips_foreign_load_build: delaying read ...\n" );
#endif /*DEBUG*/

		/* ->header() should set the dhint. It'll default to the safe
		 * SMALLTILE if header() did not set it.
		 */
		vips_image_pipelinev( load->out, load->out->dhint, NULL );

		/* Then 'start' creates the real image and 'gen' fetches 
		 * pixels for @out from @real on demand.
		 */
		if( vips_image_generate( load->out, 
			vips_foreign_load_start, 
			vips_foreign_load_generate, 
			vips_stop_one, 
			NULL, load ) ) 
			return( -1 );
	}

	return( 0 );
}

static VipsOperationFlags 
vips_foreign_load_operation_get_flags( VipsOperation *operation )
{
	VipsForeignLoad *load = VIPS_FOREIGN_LOAD( operation );

	VipsOperationFlags flags;

	flags = VIPS_OPERATION_CLASS( vips_foreign_load_parent_class )->
		get_flags( operation );
	if( load->nocache )
		flags |= VIPS_OPERATION_NOCACHE;

	return( flags );
}

static void
vips_foreign_load_class_init( VipsForeignLoadClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = (VipsOperationClass *) class;

	gobject_class->dispose = vips_foreign_load_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->build = vips_foreign_load_build;
	object_class->summary_class = vips_foreign_load_summary_class;
	object_class->new_from_string = vips_foreign_load_new_from_string;
	object_class->nickname = "fileload";
	object_class->description = _( "file loaders" );

	operation_class->get_flags = vips_foreign_load_operation_get_flags;

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignLoad, out ) );

	VIPS_ARG_FLAGS( class, "flags", 6, 
		_( "Flags" ), 
		_( "Flags for this file" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsForeignLoad, flags ),
		VIPS_TYPE_FOREIGN_FLAGS, VIPS_FOREIGN_NONE ); 

	VIPS_ARG_BOOL( class, "disc", 7, 
		_( "Disc" ), 
		_( "Open to disc" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoad, disc ),
		TRUE );

	VIPS_ARG_ENUM( class, "access", 8, 
		_( "Access" ), 
		_( "Required access pattern for this file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoad, access ),
		VIPS_TYPE_ACCESS, VIPS_ACCESS_RANDOM ); 

	VIPS_ARG_BOOL( class, "sequential", 10, 
		_( "Sequential" ), 
		_( "Sequential read only" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignLoad, sequential ),
		FALSE );

	VIPS_ARG_BOOL( class, "fail", 11, 
		_( "Fail" ), 
		_( "Fail on first warning" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoad, fail ),
		FALSE );

}

static void
vips_foreign_load_init( VipsForeignLoad *load )
{
	load->disc = TRUE;
	load->access = VIPS_ACCESS_RANDOM;
}

/**
 * Loaders can call this
 */

/**
 * vips_foreign_load_invalidate:
 * @image: image to invalidate
 *
 * Loaders can call this on the image they are making if they see a read error
 * from the load library. It signals "invalidate" on the load operation and
 * will cause it to be dropped from cache. 
 *
 * If we know a file will cause a read error, we don't want to cache the
 * failing operation, we want to make sure the image will really be opened 
 * again if our caller tries again. For example, a broken file might be 
 * replaced by a working one. 
 */
void
vips_foreign_load_invalidate( VipsImage *image )
{
	VipsOperation *operation; 

#ifdef DEBUG
	printf( "vips_foreign_load_invalidate: %p\n", image ); 
#endif /*DEBUG*/

	if( (operation = g_object_get_qdata( G_OBJECT( image ), 
		vips__foreign_load_operation )) ) {
		vips_operation_invalidate( operation ); 
	}
}

/* Abstract base class for image savers.
 */

G_DEFINE_ABSTRACT_TYPE( VipsForeignSave, vips_foreign_save, VIPS_TYPE_FOREIGN );

static void
vips_foreign_save_dispose( GObject *gobject )
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE( gobject );

	VIPS_UNREF( save->ready );

	G_OBJECT_CLASS( vips_foreign_save_parent_class )->dispose( gobject );
}

static void
vips_foreign_save_summary_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsForeignSaveClass *class = VIPS_FOREIGN_SAVE_CLASS( object_class );

	VIPS_OBJECT_CLASS( vips_foreign_save_parent_class )->
		summary_class( object_class, buf );

	vips_buf_appendf( buf, ", %s", 
		vips_enum_nick( VIPS_TYPE_SAVEABLE, class->saveable ) );
}

static VipsObject *
vips_foreign_save_new_from_string( const char *string )
{
	const char *file_op;
	GType type;
	VipsForeignSave *save;

	if( !(file_op = vips_foreign_find_save( string )) )
		return( NULL );
	type = g_type_from_name( file_op );
	g_assert( type ); 

	save = VIPS_FOREIGN_SAVE( g_object_new( type, NULL ) );
	g_object_set( save,
		"filename", string,
		NULL );

	return( VIPS_OBJECT( save ) );
}

/* Convert an image for saving. 
 */
int
vips__foreign_convert_saveable( VipsImage *in, VipsImage **ready,
	VipsSaveable saveable, VipsBandFormat *format, VipsCoding *coding,
	VipsArrayDouble *background )
{
	/* in holds a reference to the output of our chain as we build it.
	 */
	g_object_ref( in );

	/* For coded images, can this class save the coding we are in now? 
	 * Nothing to do.
	 */
	if( in->Coding != VIPS_CODING_NONE &&
		coding[in->Coding] ) {
		*ready = in;
		return( 0 );
	}

	/* For uncoded images, if this saver supports ANY bands and this 
	 * format we have nothing to do.
	 */
	if( in->Coding == VIPS_CODING_NONE &&
	        saveable == VIPS_SAVEABLE_ANY &&
		format[in->BandFmt] == in->BandFmt ) {
		*ready = in;
		return( 0 );
	}

	/* Otherwise ... we need to decode and then (possibly) recode at the
	 * end.
	 */

	/* If this is an VIPS_CODING_LABQ, we can go straight to RGB.
	 */
	if( in->Coding == VIPS_CODING_LABQ ) {
		VipsImage *out;

		if( vips_LabQ2sRGB( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	/* If this is an VIPS_CODING_RAD, we unpack to float. This could be
	 * scRGB or XYZ. 
	 */
	if( in->Coding == VIPS_CODING_RAD ) {
		VipsImage *out;

		if( vips_rad2float( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	/* If the saver supports RAD, we need to go to scRGB or XYZ. 
	 */
	if( coding[VIPS_CODING_RAD] ) {
		if( in->Type != VIPS_INTERPRETATION_scRGB &&
			in->Type != VIPS_INTERPRETATION_XYZ ) {
			VipsImage *out;

			if( vips_colourspace( in, &out, 
				VIPS_INTERPRETATION_scRGB, NULL ) ) {
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;
		}
	}

	/* If this is something other than CMYK or RAD, eg. maybe a LAB image,
	 * we need to transform to RGB.
	 */
	if( !coding[VIPS_CODING_RAD] &&
		in->Bands >= 3 &&
		in->Type != VIPS_INTERPRETATION_CMYK &&
		vips_colourspace_issupported( in ) &&
		(saveable == VIPS_SAVEABLE_RGB ||
		 saveable == VIPS_SAVEABLE_RGBA ||
		 saveable == VIPS_SAVEABLE_RGBA_ONLY ||
		 saveable == VIPS_SAVEABLE_RGB_CMYK) ) { 
		VipsImage *out;
		VipsInterpretation interpretation;

		/* Do we make RGB or RGB16? We don't want to squash a 16-bit
		 * RGB down to 8 bits if the saver supports 16. 
		 */
		if( vips_band_format_is8bit( format[in->BandFmt] ) )
			interpretation = VIPS_INTERPRETATION_sRGB;
		else
			interpretation = VIPS_INTERPRETATION_RGB16;

		if( vips_colourspace( in, &out, interpretation, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	/* VIPS_SAVEABLE_RGBA_ONLY does not support 1 or 2 bands ... convert 
	 * to sRGB. 
	 */
	if( !coding[VIPS_CODING_RAD] &&
		in->Bands < 3 &&
		vips_colourspace_issupported( in ) &&
		saveable == VIPS_SAVEABLE_RGBA_ONLY ) { 
		VipsImage *out;
		VipsInterpretation interpretation;

		/* Do we make RGB or RGB16? We don't want to squash a 16-bit
		 * RGB down to 8 bits if the saver supports 16. 
		 */
		if( vips_band_format_is8bit( format[in->BandFmt] ) )
			interpretation = VIPS_INTERPRETATION_sRGB;
		else
			interpretation = VIPS_INTERPRETATION_RGB16;

		if( vips_colourspace( in, &out, interpretation, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	/* Get the bands right. We must do this after all colourspace
	 * transforms, since they can change the number of bands. 
	 */
	if( in->Coding == VIPS_CODING_NONE ) {
		/* Do we need to flatten out an alpha channel? There needs to
		 * be an alpha there now, and this writer needs to not support
		 * alpha.
		 */
		if( (in->Bands == 2 ||
			(in->Bands == 4 && 
			 in->Type != VIPS_INTERPRETATION_CMYK)) &&
			(saveable == VIPS_SAVEABLE_MONO ||
			 saveable == VIPS_SAVEABLE_RGB ||
			 saveable == VIPS_SAVEABLE_RGB_CMYK) ) {
			VipsImage *out;

			if( vips_flatten( in, &out, 
				"background", background,
				NULL ) ) {
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;
		}

		/* Other alpha removal strategies ... just drop the extra
		 * bands.
		 */

		else if( in->Bands > 3 && 
			(saveable == VIPS_SAVEABLE_RGB ||
			 (saveable == VIPS_SAVEABLE_RGB_CMYK &&
			  in->Type != VIPS_INTERPRETATION_CMYK)) ) { 
			VipsImage *out;

			/* Don't let 4 bands though unless the image really is
			 * a CMYK.
			 *
			 * Consider a RGBA png being saved as JPG. We can
			 * write CMYK jpg, but we mustn't do that for RGBA
			 * images.
			 */
			if( vips_extract_band( in, &out, 0, 
				"n", 3,
				NULL ) ) {
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;
		}
		else if( in->Bands > 4 && 
			((saveable == VIPS_SAVEABLE_RGB_CMYK &&
			  in->Type == VIPS_INTERPRETATION_CMYK) ||
			 saveable == VIPS_SAVEABLE_RGBA ||
			 saveable == VIPS_SAVEABLE_RGBA_ONLY) ) {
			VipsImage *out;

			if( vips_extract_band( in, &out, 0, 
				"n", 4,
				NULL ) ) {
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;
		}
		else if( in->Bands > 1 && 
			saveable == VIPS_SAVEABLE_MONO ) {
			VipsImage *out;

			if( vips_extract_band( in, &out, 0, NULL ) ) {
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;
		}

		/* Else we have VIPS_SAVEABLE_ANY and we don't chop bands down.
		 */
	}

	/* Handle the ushort interpretations.
	 *
	 * RGB16 and GREY16 use 0-65535 for black-white. If we have an image
	 * tagged like this, and it has more than 8 bits (we leave crazy uchar
	 * images tagged as RGB16 alone), we'll need to get it ready for the
	 * saver.
	 */
	if( (in->Type == VIPS_INTERPRETATION_RGB16 ||
		 in->Type == VIPS_INTERPRETATION_GREY16) &&
		!vips_band_format_is8bit( in->BandFmt ) ) {
		/* If the saver supports ushort, cast to ushort. It may be
		 * float at the moment, for example.
		 *
		 * If the saver does not support ushort, automatically shift
		 * it down. This is the behaviour we want for saving an RGB16
		 * image as JPG, for example.
		 */
		if( format[VIPS_FORMAT_USHORT] == VIPS_FORMAT_USHORT ) {
			VipsImage *out;

			if( vips_cast( in, &out, VIPS_FORMAT_USHORT, NULL ) ) {
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;
		}
		else {
			VipsImage *out;

			if( vips_rshift_const1( in, &out, 8, NULL ) ) { 
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;

			/* That could have produced an int image ... make sure 
			 * we are now uchar.
			 */
			if( vips_cast( in, &out, VIPS_FORMAT_UCHAR, NULL ) ) {
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;
		}
	}

	/* Cast to the output format.
	 */
	{
		VipsImage *out;

		if( vips_cast( in, &out, format[in->BandFmt], NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	/* Does this class want a coded image? Search the coding table for the
	 * first one.
	 */
	if( coding[VIPS_CODING_NONE] ) {
		/* Already NONE, nothing to do.
		 */
	}
	else if( coding[VIPS_CODING_LABQ] ) {
		VipsImage *out;

		if( vips_Lab2LabQ( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}
	else if( coding[VIPS_CODING_RAD] ) {
		VipsImage *out;

		if( vips_float2rad( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	*ready = in;

	return( 0 );
}

static int
vips_foreign_save_build( VipsObject *object )
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE( object );

	if( save->in ) {
		VipsForeignSaveClass *class = 
			VIPS_FOREIGN_SAVE_GET_CLASS( save );
		VipsImage *ready;

		if( vips__foreign_convert_saveable( save->in, &ready,
			class->saveable, class->format_table, class->coding,
			save->background ) )
			return( -1 );

		VIPS_UNREF( save->ready );
		save->ready = ready;
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_save_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static int vips_foreign_save_format_table[10] = {
// UC  C   US  S   UI  I  F  X  D  DX 
   UC, C,  US, S,  UI, I, F, X, D, DX
};

static void
vips_foreign_save_class_init( VipsForeignSaveClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = (VipsOperationClass *) class;

	int i;

	gobject_class->dispose = vips_foreign_save_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->build = vips_foreign_save_build;
	object_class->summary_class = vips_foreign_save_summary_class;
	object_class->new_from_string = vips_foreign_save_new_from_string;
	object_class->nickname = "filesave";
	object_class->description = _( "file savers" );

	/* All savers are seqential by definition. Things like tiled tiff 
	 * write and interlaced png write, which are not, add extra caches 
	 * on their input. 
	 */
	operation_class->flags |= VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	/* Must not cache savers.
	 */
	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	/* Default to no coding allowed.
	 */
	for( i = 0; i < VIPS_CODING_LAST; i++ )
		class->coding[i] = FALSE;
	class->coding[VIPS_CODING_NONE] = TRUE;

	/* Default to no cast on save.
	 */
	class->format_table = vips_foreign_save_format_table; 

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Image to save" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSave, in ) );

	VIPS_ARG_BOOL( class, "strip", 100,
		_( "Strip" ),
		_( "Strip all metadata from image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSave, strip ),
		FALSE );

	VIPS_ARG_BOXED( class, "background", 101, 
		_( "Background" ), 
		_( "Background value" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSave, background ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_foreign_save_init( VipsForeignSave *save )
{
	save->background = vips_array_double_newv( 1, 0.0 );
}

/* Can we write this filename with this file? 
 */
static void *
vips_foreign_find_save_sub( VipsForeignSaveClass *save_class, 
	const char *filename )
{
	VipsForeignClass *class = VIPS_FOREIGN_CLASS( save_class );

	/* The suffs might be defined on an abstract base class, make sure we
	 * don't pick that.
	 */
	if( !G_TYPE_IS_ABSTRACT( G_TYPE_FROM_CLASS( class ) ) &&
		class->suffs &&
		vips_filename_suffix_match( filename, class->suffs ) )
		return( save_class );

	return( NULL );
}

/**
 * vips_foreign_find_save:
 * @filename: name to find a saver for
 *
 * Searches for an operation you could use to write to @filename.
 * Any trailing options on @filename are stripped and ignored. 
 *
 * See also: vips_foreign_find_save_buffer(), vips_image_write_to_file().
 *
 * Returns: the name of an operation on success, %NULL on error
 */
const char *
vips_foreign_find_save( const char *name )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	VipsForeignSaveClass *save_class;

	vips__filename_split8( name, filename, option_string );

	if( !(save_class = (VipsForeignSaveClass *) vips_foreign_map( 
		"VipsForeignSave",
		(VipsSListMap2Fn) vips_foreign_find_save_sub, 
		(void *) filename, NULL )) ) {
		vips_error( "VipsForeignSave",
			_( "\"%s\" is not a known file format" ), name );

		return( NULL );
	}

	return( G_OBJECT_CLASS_NAME( save_class ) );
}

/* Kept for early vips8 API compat.
 */

int
vips_foreign_save( VipsImage *in, const char *name, ... )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	int result;

	vips__filename_split8( name, filename, option_string );

	if( !(operation_name = vips_foreign_find_save( filename )) )
		return( -1 );

	va_start( ap, name );
	result = vips_call_split_option_string( operation_name, option_string, 
		ap, in, filename );
	va_end( ap );

	return( result );
}

/* Can we write this buffer with this file type?
 */
static void *
vips_foreign_find_save_buffer_sub( VipsForeignSaveClass *save_class, 
	const char *suffix )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( save_class );
	VipsForeignClass *class = VIPS_FOREIGN_CLASS( save_class );

	if( class->suffs &&
		vips_ispostfix( object_class->nickname, "_buffer" ) &&
		vips_filename_suffix_match( suffix, class->suffs ) )
		return( save_class );

	return( NULL );
}

/**
 * vips_foreign_find_save_buffer:
 * @suffix: name to find a saver for
 *
 * Searches for an operation you could use to write to a buffer in @suffix
 * format. 
 *
 * See also: vips_image_write_to_buffer().
 *
 * Returns: the name of an operation on success, %NULL on error
 */
const char *
vips_foreign_find_save_buffer( const char *name )
{
	char suffix[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	VipsForeignSaveClass *save_class;

	vips__filename_split8( name, suffix, option_string );

	if( !(save_class = (VipsForeignSaveClass *) vips_foreign_map( 
		"VipsForeignSave",
		(VipsSListMap2Fn) vips_foreign_find_save_buffer_sub, 
		(void *) suffix, NULL )) ) {
		vips_error( "VipsForeignSave",
			_( "\"%s\" is not a known buffer format" ), name );

		return( NULL );
	}

	return( G_OBJECT_CLASS_NAME( save_class ) );
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_foreign_operation_init( void )
{
	extern GType vips_foreign_load_rad_get_type( void ); 
	extern GType vips_foreign_save_rad_file_get_type( void ); 
	extern GType vips_foreign_save_rad_buffer_get_type( void ); 
	extern GType vips_foreign_load_mat_get_type( void ); 
	extern GType vips_foreign_load_ppm_get_type( void ); 
	extern GType vips_foreign_save_ppm_get_type( void ); 
	extern GType vips_foreign_load_png_get_type( void ); 
	extern GType vips_foreign_load_png_buffer_get_type( void ); 
	extern GType vips_foreign_save_png_file_get_type( void ); 
	extern GType vips_foreign_save_png_buffer_get_type( void ); 
	extern GType vips_foreign_load_csv_get_type( void ); 
	extern GType vips_foreign_save_csv_get_type( void ); 
	extern GType vips_foreign_load_matrix_get_type( void ); 
	extern GType vips_foreign_save_matrix_get_type( void ); 
	extern GType vips_foreign_print_matrix_get_type( void ); 
	extern GType vips_foreign_load_fits_get_type( void ); 
	extern GType vips_foreign_save_fits_get_type( void ); 
	extern GType vips_foreign_load_analyze_get_type( void ); 
	extern GType vips_foreign_load_openexr_get_type( void ); 
	extern GType vips_foreign_load_openslide_get_type( void ); 
	extern GType vips_foreign_load_jpeg_file_get_type( void ); 
	extern GType vips_foreign_load_jpeg_buffer_get_type( void ); 
	extern GType vips_foreign_save_jpeg_file_get_type( void ); 
	extern GType vips_foreign_save_jpeg_buffer_get_type( void ); 
	extern GType vips_foreign_save_jpeg_mime_get_type( void ); 
	extern GType vips_foreign_load_tiff_file_get_type( void ); 
	extern GType vips_foreign_load_tiff_buffer_get_type( void ); 
	extern GType vips_foreign_save_tiff_file_get_type( void ); 
	extern GType vips_foreign_save_tiff_buffer_get_type( void ); 
	extern GType vips_foreign_load_vips_get_type( void ); 
	extern GType vips_foreign_save_vips_get_type( void ); 
	extern GType vips_foreign_load_raw_get_type( void ); 
	extern GType vips_foreign_save_raw_get_type( void ); 
	extern GType vips_foreign_save_raw_fd_get_type( void ); 
	extern GType vips_foreign_load_magick_file_get_type( void ); 
	extern GType vips_foreign_load_magick_buffer_get_type( void ); 
	extern GType vips_foreign_load_magick7_file_get_type( void ); 
	extern GType vips_foreign_load_magick7_buffer_get_type( void ); 
	extern GType vips_foreign_save_dz_file_get_type( void ); 
	extern GType vips_foreign_save_dz_buffer_get_type( void ); 
	extern GType vips_foreign_load_webp_file_get_type( void ); 
	extern GType vips_foreign_load_webp_buffer_get_type( void ); 
	extern GType vips_foreign_save_webp_file_get_type( void ); 
	extern GType vips_foreign_save_webp_buffer_get_type( void ); 
	extern GType vips_foreign_load_pdf_get_type( void ); 
	extern GType vips_foreign_load_pdf_file_get_type( void ); 
	extern GType vips_foreign_load_pdf_buffer_get_type( void ); 
	extern GType vips_foreign_load_svg_get_type( void ); 
	extern GType vips_foreign_load_svg_file_get_type( void ); 
	extern GType vips_foreign_load_svg_buffer_get_type( void ); 
	extern GType vips_foreign_load_gif_get_type( void ); 
	extern GType vips_foreign_load_gif_file_get_type( void ); 
	extern GType vips_foreign_load_gif_buffer_get_type( void ); 

	vips_foreign_load_csv_get_type(); 
	vips_foreign_save_csv_get_type(); 
	vips_foreign_load_matrix_get_type(); 
	vips_foreign_save_matrix_get_type(); 
	vips_foreign_print_matrix_get_type(); 
	vips_foreign_load_raw_get_type(); 
	vips_foreign_save_raw_get_type(); 
	vips_foreign_save_raw_fd_get_type(); 
	vips_foreign_load_vips_get_type(); 
	vips_foreign_save_vips_get_type(); 

#ifdef HAVE_ANALYZE
	vips_foreign_load_analyze_get_type(); 
#endif /*HAVE_ANALYZE*/

#ifdef HAVE_PPM
	vips_foreign_load_ppm_get_type(); 
	vips_foreign_save_ppm_get_type(); 
#endif /*HAVE_PPM*/

#ifdef HAVE_RADIANCE
	vips_foreign_load_rad_get_type(); 
	vips_foreign_save_rad_file_get_type(); 
	vips_foreign_save_rad_buffer_get_type(); 
#endif /*HAVE_RADIANCE*/

#ifdef HAVE_POPPLER
	vips_foreign_load_pdf_get_type(); 
	vips_foreign_load_pdf_file_get_type(); 
	vips_foreign_load_pdf_buffer_get_type(); 
#endif /*HAVE_POPPLER*/

#ifdef HAVE_RSVG
	vips_foreign_load_svg_get_type(); 
	vips_foreign_load_svg_file_get_type(); 
	vips_foreign_load_svg_buffer_get_type(); 
#endif /*HAVE_RSVG*/

#ifdef HAVE_GIFLIB
	vips_foreign_load_gif_get_type(); 
	vips_foreign_load_gif_file_get_type(); 
	vips_foreign_load_gif_buffer_get_type(); 
#endif /*HAVE_GIFLIB*/

#ifdef HAVE_GSF
	vips_foreign_save_dz_file_get_type(); 
	vips_foreign_save_dz_buffer_get_type(); 
#endif /*HAVE_GSF*/

#ifdef HAVE_PNG
	vips_foreign_load_png_get_type(); 
	vips_foreign_load_png_buffer_get_type(); 
	vips_foreign_save_png_file_get_type(); 
	vips_foreign_save_png_buffer_get_type(); 
#endif /*HAVE_PNG*/

#ifdef HAVE_MATIO
	vips_foreign_load_mat_get_type(); 
#endif /*HAVE_MATIO*/

#ifdef HAVE_JPEG
	vips_foreign_load_jpeg_file_get_type(); 
	vips_foreign_load_jpeg_buffer_get_type(); 
	vips_foreign_save_jpeg_file_get_type(); 
	vips_foreign_save_jpeg_buffer_get_type(); 
	vips_foreign_save_jpeg_mime_get_type(); 
#endif /*HAVE_JPEG*/

#ifdef HAVE_LIBWEBP
	vips_foreign_load_webp_file_get_type(); 
	vips_foreign_load_webp_buffer_get_type(); 
	vips_foreign_save_webp_file_get_type(); 
	vips_foreign_save_webp_buffer_get_type(); 
#endif /*HAVE_LIBWEBP*/

#ifdef HAVE_TIFF
	vips_foreign_load_tiff_file_get_type(); 
	vips_foreign_load_tiff_buffer_get_type(); 
	vips_foreign_save_tiff_file_get_type(); 
	vips_foreign_save_tiff_buffer_get_type(); 
#endif /*HAVE_TIFF*/

#ifdef HAVE_OPENSLIDE
	vips_foreign_load_openslide_get_type(); 
#endif /*HAVE_OPENSLIDE*/

#ifdef HAVE_MAGICK
	vips_foreign_load_magick_file_get_type(); 
	vips_foreign_load_magick_buffer_get_type(); 
#endif /*HAVE_MAGICK*/

#ifdef HAVE_MAGICK7
	vips_foreign_load_magick7_file_get_type(); 
	vips_foreign_load_magick7_buffer_get_type(); 
#endif /*HAVE_MAGICK7*/

#ifdef HAVE_CFITSIO
	vips_foreign_load_fits_get_type(); 
	vips_foreign_save_fits_get_type(); 
#endif /*HAVE_CFITSIO*/

#ifdef HAVE_OPENEXR
	vips_foreign_load_openexr_get_type(); 
#endif /*HAVE_OPENEXR*/

	vips__foreign_load_operation = 
		g_quark_from_static_string( "vips-foreign-load-operation" ); 
}
