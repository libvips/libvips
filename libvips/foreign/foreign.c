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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

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
 * Matlab, Radiance, RAW, FITS, WebP and VIPS. It also includes import filters 
 * which can load with libMagick and with OpenSlide. 
 */

/**
 * VipsForeignFlags: 
 * @VIPS_FOREIGN_NONE: no flags set
 * @VIPS_FOREIGN_PARTIAL: the image may be read lazilly
 * @VIPS_FOREIGN_BIGENDIAN: image pixels are most-significant byte first
 * @VIPS_FOREIGN_SEQUENTIAL: top-to-bottom lazy reading
 *
 * Some hints about the image loader.
 *
 * @VIPS_FOREIGN_PARTIAL means that the image can be read directly from the
 * file without needing to be unpacked to a temporary image first. 
 *
 * @VIPS_FOREIGN_SEQUENTIAL means that the loader supports lazy reading, but
 * only top-to-bottom (sequential) access. Formats like PNG can read sets of
 * scanlines, for example, but only in order. 
 *
 * If neither PARTIAL or SEQUENTIAL is set, the loader only supports whole
 * image read. Setting both PARTIAL and SEQUENTIAL is an error.
 *
 * @VIPS_FOREIGN_BIGENDIAN means that image pixels are most-significant byte
 * first. Depending on the native byte order of the host machine, you may
 * need to swap bytes. See vips_copy().
 */

/**
 * VipsForeignClass:
 *
 * The suffix list is used to select a format to save a file in, and to pick a
 * loader if you don't define is_a().
 *
 * You should also define @nickname and @description in #VipsObject. 
 */

/**
 * VipsForeignLoad:
 *
 * @header() must set at least the header fields of @out. @load(), if defined,
 * must load the pixels to @real.
 */

/**
 * VipsForeignLoadClass:
 *
 * Add a new loader to VIPS by subclassing #VipsForeignLoad. Subclasses need to 
 * implement at least @header().
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
 */

/**
 * VipsForeignSaveClass:
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

	object_class->nickname = "file";
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

	if( load_class->is_a ) {
		if( load_class->is_a( filename ) ) 
			return( load_class );
	}
	else if( class->suffs && 
		vips_filename_suffix_match( filename, class->suffs ) )
		return( load_class );

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
	VipsObjectClass *class;
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
	VipsObjectClass *class;
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
	VipsObjectClass *class;

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
		vips_warn( class->nickname, "%s", 
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

	if( load->sequential ) {
		vips_warn( class->nickname, "%s", 
			_( "ignoring deprecated \"sequential\" mode" ) ); 
		vips_warn( class->nickname, "%s", 
			_( "please use \"access\" instead" ) ); 
	}

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

}

static void
vips_foreign_load_init( VipsForeignLoad *load )
{
	load->disc = TRUE;
	load->access = VIPS_ACCESS_RANDOM;
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

/* Generate the saveable image.
 */
static int
vips_foreign_convert_saveable( VipsForeignSave *save )
{
	VipsForeignSaveClass *class = VIPS_FOREIGN_SAVE_GET_CLASS( save );
	VipsImage *in = save->in;

	/* in holds a reference to the output of our chain as we build it.
	 */
	g_object_ref( in );

	/* For coded images, can this class save the coding we are in now? 
	 * Nothing to do.
	 */
	if( in->Coding != VIPS_CODING_NONE &&
		class->coding[in->Coding] ) {
		VIPS_UNREF( save->ready );
		save->ready = in;

		return( 0 );
	}

	/* For uncoded images, if this saver supports ANY bands and this 
	 * format we have nothing to do.
	 */
	if( in->Coding == VIPS_CODING_NONE &&
	        class->saveable == VIPS_SAVEABLE_ANY &&
		class->format_table[in->BandFmt] == in->BandFmt ) {
		VIPS_UNREF( save->ready );
		save->ready = in;

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
	if( class->coding[VIPS_CODING_RAD] ) {
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
	if( !class->coding[VIPS_CODING_RAD] &&
		in->Bands >= 3 &&
		in->Type != VIPS_INTERPRETATION_CMYK &&
		vips_colourspace_issupported( in ) &&
		(class->saveable == VIPS_SAVEABLE_RGB ||
		 class->saveable == VIPS_SAVEABLE_RGBA ||
		 class->saveable == VIPS_SAVEABLE_RGBA_ONLY ||
		 class->saveable == VIPS_SAVEABLE_RGB_CMYK) ) { 
		VipsImage *out;
		VipsInterpretation interpretation;

		/* Do we make RGB or RGB16? We don't want to squash a 16-bit
		 * RGB down to 8 bits if the saver supports 16. 
		 */
		if( vips_band_format_is8bit( 
			class->format_table[in->BandFmt] ) )
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
	if( !class->coding[VIPS_CODING_RAD] &&
		in->Bands < 3 &&
		vips_colourspace_issupported( in ) &&
		class->saveable == VIPS_SAVEABLE_RGBA_ONLY ) { 
		VipsImage *out;
		VipsInterpretation interpretation;

		/* Do we make RGB or RGB16? We don't want to squash a 16-bit
		 * RGB down to 8 bits if the saver supports 16. 
		 */
		if( vips_band_format_is8bit( 
			class->format_table[in->BandFmt] ) )
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
			(class->saveable == VIPS_SAVEABLE_MONO ||
			 class->saveable == VIPS_SAVEABLE_RGB ||
			 class->saveable == VIPS_SAVEABLE_RGB_CMYK) ) {
			VipsImage *out;

			if( vips_flatten( in, &out, 
				"background", save->background,
				"max_alpha", 
					in->BandFmt == VIPS_FORMAT_USHORT ?
						65535.0 : 255.0, 
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
			(class->saveable == VIPS_SAVEABLE_RGB ||
			 (class->saveable == VIPS_SAVEABLE_RGB_CMYK &&
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
			((class->saveable == VIPS_SAVEABLE_RGB_CMYK &&
			  in->Type == VIPS_INTERPRETATION_CMYK) ||
			 class->saveable == VIPS_SAVEABLE_RGBA ||
			 class->saveable == VIPS_SAVEABLE_RGBA_ONLY) ) {
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
			class->saveable == VIPS_SAVEABLE_MONO ) {
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
		if( class->format_table[VIPS_FORMAT_USHORT] == 
			VIPS_FORMAT_USHORT ) {
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

		if( vips_cast( in, &out, 
			class->format_table[in->BandFmt], NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	/* Does this class want a coded image? Search the coding table for the
	 * first one.
	 */
	if( class->coding[VIPS_CODING_NONE] ) {
		/* Already NONE, nothing to do.
		 */
	}
	else if( class->coding[VIPS_CODING_LABQ] ) {
		VipsImage *out;

		if( vips_Lab2LabQ( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}
	else if( class->coding[VIPS_CODING_RAD] ) {
		VipsImage *out;

		if( vips_float2rad( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	VIPS_UNREF( save->ready );
	save->ready = in;

	return( 0 );
}

static int
vips_foreign_save_build( VipsObject *object )
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE( object );

	if( save->in &&
		vips_foreign_convert_saveable( save ) )
		return( -1 );

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

	if( class->suffs &&
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
	extern GType vips_foreign_save_rad_get_type( void ); 
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
	extern GType vips_foreign_save_tiff_get_type( void ); 
	extern GType vips_foreign_load_vips_get_type( void ); 
	extern GType vips_foreign_save_vips_get_type( void ); 
	extern GType vips_foreign_load_raw_get_type( void ); 
	extern GType vips_foreign_save_raw_get_type( void ); 
	extern GType vips_foreign_save_raw_fd_get_type( void ); 
	extern GType vips_foreign_load_magick_file_get_type( void ); 
	extern GType vips_foreign_load_magick_buffer_get_type( void ); 
	extern GType vips_foreign_save_dz_get_type( void ); 
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
	vips_foreign_save_rad_get_type(); 
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
	vips_foreign_save_dz_get_type(); 
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
	vips_foreign_save_tiff_get_type(); 
#endif /*HAVE_TIFF*/

#ifdef HAVE_OPENSLIDE
	vips_foreign_load_openslide_get_type(); 
#endif /*HAVE_OPENSLIDE*/

#ifdef HAVE_MAGICK
	vips_foreign_load_magick_file_get_type(); 
	vips_foreign_load_magick_buffer_get_type(); 
#endif /*HAVE_MAGICK*/

#ifdef HAVE_CFITSIO
	vips_foreign_load_fits_get_type(); 
	vips_foreign_save_fits_get_type(); 
#endif /*HAVE_CFITSIO*/

#ifdef HAVE_OPENEXR
	vips_foreign_load_openexr_get_type(); 
#endif /*HAVE_OPENEXR*/
}

/**
 * vips_vipsload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read in a vips image. 
 *
 * See also: vips_vipssave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_vipsload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "vipsload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_vipssave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write @in to @filename in VIPS format.
 *
 * See also: vips_vipsload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_vipssave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "vipssave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_magickload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @all_frames: %gboolean, load all frames in sequence
 * @density: string, canvas resolution for rendering vector formats like SVG
 *
 * Read in an image using libMagick, the ImageMagick library. This library can
 * read more than 80 file formats, including SVG, BMP, EPS, DICOM and many 
 * others.
 * The reader can handle any ImageMagick image, including the float and double
 * formats. It will work with any quantum size, including HDR. Any metadata
 * attached to the libMagick image is copied on to the VIPS image.
 *
 * The reader should also work with most versions of GraphicsMagick. See the
 * "--with-magickpackage" configure option.
 *
 * Normally it will only load the first image in a many-image sequence (such
 * as a GIF). Set @all_frames to true to read the whole image sequence. 
 *
 * @density is "WxH" in DPI, e.g. "600x300" or "600" (default is "72x72"). See
 * the [density 
 * docs](http://www.imagemagick.org/script/command-line-options.php#density) 
 * on the imagemagick website.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magickload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "magickload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_magickload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @all_frames: %gboolean, load all frames in sequence
 * @density: string, canvas resolution for rendering vector formats like SVG
 *
 * Read an image memory block using libMagick into a VIPS image. Exactly as
 * vips_magickload(), but read from a memory source. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_magickload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magickload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "magickload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_tiffload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @page: int, load this page
 *
 * Read a TIFF file into a VIPS image. It is a full baseline TIFF 6 reader, 
 * with extensions for tiled images, multipage images, LAB colour space, 
 * pyramidal images and JPEG compression. including CMYK and YCbCr.
 *
 * @page means load this page from the file. By default the first page (page
 * 0) is read.
 *
 * Any ICC profile is read and attached to the VIPS image. Any XMP metadata is
 * read and attached to the image. 
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_tiffload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "tiffload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_tiffload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @page: %gint, load this page
 *
 * Read a TIFF-formatted memory block into a VIPS image. Exactly as
 * vips_tiffload(), but read from a memory source. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_tiffload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_tiffload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "tiffload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_tiffsave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @compression: use this #VipsForeignTiffCompression
 * @Q: %gint quality factor
 * @predictor: use this #VipsForeignTiffPredictor
 * @profile: filename of ICC profile to attach
 * @tile: set %TRUE to write a tiled tiff
 * @tile_width: %gint for tile size
 * @tile_height: %gint for tile size
 * @pyramid: set %TRUE to write an image pyramid
 * @squash: set %TRUE to squash 8-bit images down to 1 bit
 * @miniswhite: set %TRUE to write 1-bit images as MINISWHITE
 * @resunit: #VipsForeignTiffResunit for resolution unit
 * @xres: %gdouble horizontal resolution in pixels/mm
 * @yres: %gdouble vertical resolution in pixels/mm
 * @bigtiff: set %TRUE to write a BigTiff file
 *
 * Write a VIPS image to a file as TIFF.
 *
 * Use @compression to set the tiff compression. Currently jpeg, packbits,
 * fax4, lzw, none and deflate are supported. The default is no compression.
 * JPEG compression is a good lossy compressor for photographs, packbits is 
 * good for 1-bit images, and deflate is the best lossless compression TIFF 
 * can do. LZW has patent problems and is no longer recommended.
 *
 * Use @Q to set the JPEG compression factor. Default 75.
 *
 * Use @predictor to set the predictor for lzw and deflate compression. 
 *
 * Predictor is not set by default. There are three predictor values recognised
 * at the moment (2007, July): 1 is no prediction, 2 is a horizontal 
 * differencing and 3 is a floating point predictor. Refer to the libtiff 
 * specifications for further discussion of various predictors. In short, 
 * predictor helps to better compress image, especially in case of digital 
 * photos or scanned images and bit depths > 8. Try it to find whether it 
 * works for your images.
 *
 * Use @profile to give the filename of a profile to be embedded in the TIFF.
 * This does not affect the pixels which are written, just the way 
 * they are tagged. You can use the special string "none" to mean 
 * "don't attach a profile".
 *
 * If no profile is specified and the VIPS header 
 * contains an ICC profile named VIPS_META_ICC_NAME ("icc-profile-data"), the
 * profile from the VIPS header will be attached.
 *
 * Set @tile to TRUE to write a tiled tiff.  By default tiff are written in
 * strips. Use @tile_width and @tile_height to set the tile size. The defaiult
 * is 128 by 128.
 *
 * Set @pyramid to write the image as a set of images, one per page, of
 * decreasing size. 
 *
 * Set @squash to make 8-bit uchar images write as 1-bit TIFFs. Values >128
 * are written as white, values <=128 as black. Normally vips will write
 * MINISBLACK TIFFs where black is a 0 bit, but if you set @miniswhite, it
 * will use 0 for a white bit. Many pre-press applications only work with
 * images which use this sense. @miniswhite only affects one-bit images, it
 * does nothing for greyscale images. 
 *
 * Use @resunit to override the default resolution unit.  
 * The default 
 * resolution unit is taken from the header field "resolution-unit"
 * (#VIPS_META_RESOLUTION_UNIT in C). If this field is not set, then 
 * VIPS defaults to cm.
 *
 * Use @xres and @yres to override the default horizontal and vertical
 * resolutions. By default these values are taken from the VIPS image header. 
 * libvips resolution is always in pixels per millimetre.
 *
 * Set @bigtiff to attempt to write a bigtiff. 
 * Bigtiff is a variant of the TIFF
 * format that allows more than 4GB in a file.
 *
 * If @in has a field called VIPS_META_XMP_NAME ("xmp-data") it is written to
 * the tiff image. 
 *
 * See also: vips_tiffload(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_tiffsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "tiffsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_jpegload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @shrink: %gint, shrink by this much on load
 * @fail: %gboolean, fail on warnings
 * @autorotate: %gboolean, use exif Orientation tag to rotate the image during load
 *
 * Read a JPEG file into a VIPS image. It can read most 8-bit JPEG images, 
 * including CMYK and YCbCr.
 *
 * @shrink means shrink by this integer factor during load.  Possible values 
 * are 1, 2, 4 and 8. Shrinking during read is very much faster than 
 * decompressing the whole image and then shrinking later.
 *
 * Setting @fail to %TRUE makes the JPEG reader fail on any warnings. 
 * This can be useful for detecting truncated files, for example. Normally 
 * reading these produces a warning, but no fatal error.  
 *
 * Setting @autorotate to %TRUE will make the loader interpret the EXIF
 * Orientation field and automatically rotate the image appropriately during
 * load. After rotation, the Orientation tag will be removed to prevent
 * accidental double-rotation.  
 *
 * Using @autorotate can be much slower than doing the rotate later
 * in processing. See vips_autorot().
 *
 * Example:
 *
 * |[
 * vips_jpegload( "fred.jpg", &amp;out,
 * 	"shrink", 8,
 * 	"fail", TRUE,
 * 	NULL );
 * ]|
 *
 * Any embedded ICC profiles are ignored: you always just get the RGB from 
 * the file. Instead, the embedded profile will be attached to the image as 
 * @VIPS_META_ICC_NAME ("icc-profile-data"). You need to use something like 
 * vips_icc_import() to get CIE values from the file. 
 *
 * EXIF metadata is attached as @VIPS_META_EXIF_NAME ("exif-data"), IPCT as
 * @VIPS_META_IPCT_NAME ("ipct-data"), and XMP as VIPS_META_XMP_NAME
 * ("xmp-data").
 *
 * The int metadata item "jpeg-multiscan" is set to the result of 
 * jpeg_has_multiple_scans(). Interlaced jpeg images need a large amount of
 * memory to load, so this field gives callers a chance to handle these
 * images differently.
 *
 * The EXIF thumbnail, if present, is attached to the image as 
 * "jpeg-thumbnail-data". See vips_image_get_blob().
 *
 * This function only reads the image header and does not decompress any pixel
 * data. Decompression only occurs when pixels are accessed.
 *
 * See also: vips_jpegload_buffer(), vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jpegload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "jpegload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_jpegload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @shrink: %gint, shrink by this much on load
 * @fail: %gboolean, fail on warnings
 *
 * Read a JPEG-formatted memory block into a VIPS image. Exactly as
 * vips_jpegload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_jpegload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jpegload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "jpegload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_jpegsave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @Q: %gint, quality factor
 * @profile: filename of ICC profile to attach
 * @optimize_coding: %gboolean, compute optimal Huffman coding tables
 * @interlace: %gboolean, write an interlaced (progressive) jpeg
 * @strip: %gboolean, remove all metadata from image
 * @no-subsample: %gboolean, disable chroma subsampling
 * @trellis_quant: %gboolean, apply trellis quantisation to each 8x8 block
 * @overshoot_deringing: %gboolean, overshoot samples with extreme values
 * @optimize_scans: %gboolean, split DCT coefficients into separate scans
 *
 * Write a VIPS image to a file as JPEG.
 *
 * Use @Q to set the JPEG compression factor. Default 75.
 *
 * Use @profile to give the filename of a profile to be embedded in the JPEG.
 * This does not affect the pixels which are written, just the way 
 * they are tagged. You can use the special string "none" to mean 
 * "don't attach a profile".
 *
 * If no profile is specified and the VIPS header 
 * contains an ICC profile named VIPS_META_ICC_NAME ("icc-profile-data"), the
 * profile from the VIPS header will be attached.
 *
 * The image is automatically converted to RGB, Monochrome or CMYK before 
 * saving. 
 *
 * EXIF data is constructed from @VIPS_META_EXIF_NAME ("exif-data"), then
 * modified with any other related tags on the image before being written to
 * the file. 
 *
 * IPCT as @VIPS_META_IPCT_NAME ("ipct-data") and XMP as VIPS_META_XMP_NAME
 * ("xmp-data") are coded and attached. 
 *
 * If @optimize_coding is set, the Huffman tables are optimised. This is
 * sllightly slower and produces slightly smaller files. 
 *
 * If @interlace is set, the jpeg files will be interlaced (progressive jpeg,
 * in jpg parlance). These files may be better for display over a slow network
 * conection, but need much more memory to encode and decode. 
 *
 * If @strip is set, no EXIF data, IPCT data, ICC profile or XMP metadata is 
 * written into the output file. 
 *
 * If @no-subsample is set, chrominance subsampling is disabled. This will 
 * improve quality at the cost of larger file size. Useful for high Q factors. 
 *
 * If @trellis_quant is set and the version of libjpeg supports it
 * (e.g. mozjpeg >= 3.0), apply trellis quantisation to each 8x8 block.
 * Reduces file size but increases compression time.
 *
 * If @overshoot_deringing is set and the version of libjpeg supports it
 * (e.g. mozjpeg >= 3.0), apply overshooting to samples with extreme values
 * for example 0 and 255 for 8-bit. Overshooting may reduce ringing artifacts
 * from compression, in particular in areas where black text appears on a
 * white background.
 *
 * If @optimize_scans is set and the version of libjpeg supports it
 * (e.g. mozjpeg >= 3.0), split the spectrum of DCT coefficients into
 * separate scans. Reduces file size but increases compression time.
 *
 * See also: vips_jpegsave_buffer(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jpegsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "jpegsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_jpegsave_buffer:
 * @in: image to save 
 * @buf: return output buffer here
 * @len: return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @Q: JPEG quality factor
 * @profile: attach this ICC profile
 * @optimize_coding: compute optimal Huffman coding tables
 * @interlace: write an interlaced (progressive) jpeg
 * @strip: remove all metadata from image
 * @no-subsample: disable chroma subsampling
 * @trellis_quant: %gboolean, apply trellis quantisation to each 8x8 block
 * @overshoot_deringing: %gboolean, overshoot samples with extreme values
 * @optimize_scans: %gboolean, split DCT coefficients into separate scans
 *
 * As vips_jpegsave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_jpegsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jpegsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "jpegsave_buffer", ap, in, &area );
	va_end( ap );

	if( !result &&
		area ) { 
		if( buf ) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if( len ) 
			*len = area->length;

		vips_area_unref( area );
	}

	return( result );
}

/**
 * vips_jpegsave_mime:
 * @in: image to save 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @Q: JPEG quality factor
 * @profile: attach this ICC profile
 * @optimize_coding: compute optimal Huffman coding tables
 * @strip: remove all metadata from image
 * @no-subsample: disable chroma subsampling
 * @trellis_quant: %gboolean, apply trellis quantisation to each 8x8 block
 * @overshoot_deringing: %gboolean, overshoot samples with extreme values
 * @optimize_scans: %gboolean, split DCT coefficients into separate scans
 *
 * As vips_jpegsave(), but save as a mime jpeg on stdout.
 *
 * See also: vips_jpegsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jpegsave_mime( VipsImage *in, ... )
{
	va_list ap;
	int result;

	va_start( ap, in );
	result = vips_call_split( "jpegsave_mime", ap, in );
	va_end( ap );

	return( result );
}

/**
 * vips_webpload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @shrink: %gint, shrink by this much on load
 *
 * Read a WebP file into a VIPS image. 
 *
 * Use @shrink to specify a shrink-on-load factor.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "webpload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_webpload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @shrink: %gint, shrink by this much on load
 *
 * Read a WebP-formatted memory block into a VIPS image. Exactly as
 * vips_webpload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_webpload()
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "webpload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_webpsave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @Q: quality factor
 * @lossless: enables lossless compression
 * @preset: #VipsForeignWebpPreset choose lossy compression preset
 * @smart_subsample: enables high quality chroma subsampling
 *
 * See also: vips_webpload(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "webpsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_webpsave_buffer:
 * @in: image to save 
 * @buf: return output buffer here
 * @len: return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @Q: JPEG quality factor
 * @lossless: enables lossless compression
 * @preset: #VipsForeignWebpPreset choose lossy compression preset
 * @smart_subsample: enables high quality chroma subsampling
 *
 * See also: vips_webpsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "webpsave_buffer", ap, in, &area );
	va_end( ap );

	if( !result &&
		area ) { 
		if( buf ) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if( len ) 
			*len = area->length;

		vips_area_unref( area );
	}

	return( result );
}

/**
 * vips_webpsave_mime:
 * @in: image to save 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @Q: quality factor
 *
 * As vips_webpsave(), but save as a mime webp on stdout.
 *
 * See also: vips_webpsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave_mime( VipsImage *in, ... )
{
	va_list ap;
	int result;

	va_start( ap, in );
	result = vips_call_split( "webpsave_mime", ap, in );
	va_end( ap );

	return( result );
}

/**
 * vips_openexrload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a OpenEXR file into a VIPS image. 
 *
 * The reader can handle scanline and tiled OpenEXR images. It can't handle
 * OpenEXR colour management, image attributes, many pixel formats, anything
 * other than RGBA.
 *
 * This reader uses the rather limited OpenEXR C API. It should really be
 * redone in C++.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_openexrload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "openexrload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_openslideload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @level: load this level
 * @associated: load this associated image
 * @autocrop: crop to image bounds
 *
 * Read a virtual slide supported by the OpenSlide library into a VIPS image.
 * OpenSlide supports images in Aperio, Hamamatsu, MIRAX, Sakura, Trestle,
 * and Ventana formats.
 *
 * To facilitate zooming, virtual slide formats include multiple scaled-down
 * versions of the high-resolution image.  These are typically called
 * "levels".  By default, vips_openslideload() reads the highest-resolution
 * level (level 0).  Set @level to the level number you want.
 *
 * In addition to the slide image itself, virtual slide formats sometimes
 * include additional images, such as a scan of the slide's barcode.
 * OpenSlide calls these "associated images".  To read an associated image,
 * set @associated to the image's name.
 * A slide's associated images are listed in the
 * "slide-associated-images" metadata item.
 *
 * The output of this operator is always RGBA.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_openslideload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "openslideload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_fitsload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a FITS image file into a VIPS image. 
 *
 * This operation can read images with up to three dimensions. Any higher
 * dimensions must be empty. 
 *
 * It can read 8, 16 and 32-bit integer images, signed and unsigned, float and 
 * double. 
 *
 * FITS metadata is attached with the "fits-" prefix.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_fitsload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "fitsload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_fitssave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write a VIPS image to a file in FITS format.
 *
 * See also: vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_fitssave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "fitssave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_pngload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * Read a PNG file into a VIPS image. It can read all png images, including 8-
 * and 16-bit images, 1 and 3 channel, with and without an alpha channel.
 *
 * Any ICC profile is read and attached to the VIPS image.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "pngload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_pngload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a PNG-formatted memory block into a VIPS image. It can read all png 
 * images, including 8- and 16-bit images, 1 and 3 channel, with and without 
 * an alpha channel.
 *
 * Any ICC profile is read and attached to the VIPS image.
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_pngload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "pngload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_pngsave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @compression: compression level
 * @interlace: interlace image
 * @profile: ICC profile to embed
 * @filter: #VipsForeignPngFilter row filter flag(s)
 *
 * Write a VIPS image to a file as PNG.
 *
 * @compression means compress with this much effort (0 - 9). Default 6.
 *
 * Set @interlace to %TRUE to interlace the image with ADAM7 
 * interlacing. Beware
 * than an interlaced PNG can be up to 7 times slower to write than a
 * non-interlaced image.
 *
 * Use @profile to give the filename of a profile to be embedded in the PNG.
 * This does not affect the pixels which are written, just the way 
 * they are tagged. You can use the special string "none" to mean 
 * "don't attach a profile".
 *
 * If @profile is specified and the VIPS header 
 * contains an ICC profile named VIPS_META_ICC_NAME ("icc-profile-data"), the
 * profile from the VIPS header will be attached.
 *
 * Use @filter to specify one or more filters (instead of adaptive filtering),
 * see #VipsForeignPngFilter. 
 *
 * The image is automatically converted to RGB, RGBA, Monochrome or Mono +
 * alpha before saving. Images with more than one byte per band element are
 * saved as 16-bit PNG, others are saved as 8-bit PNG.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "pngsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_pngsave_buffer:
 * @in: image to save 
 * @buf: return output buffer here
 * @len: return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @compression: compression level
 * @interlace: interlace image
 * @profile: ICC profile to embed
 * @filter: libpng row filter flag(s)
 *
 * As vips_pngsave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_pngsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "pngsave_buffer", ap, in, &area );
	va_end( ap );

	if( !result &&
		area ) { 
		if( buf ) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if( len ) 
			*len = area->length;

		vips_area_unref( area );
	}

	return( result );
}

/**
 * vips_matload:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a Matlab save file into a VIPS image. 
 *
 * This operation searches the save
 * file for the first array variable with between 1 and 3 dimensions and loads
 * it as an image. It will not handle complex images. It does not handle
 * sparse matrices. 
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_matload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "matload", ap, filename, out ); 
	va_end( ap );

	return( result );
}

/**
 * vips_pdfload:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @page: %gint, load this page, numbered from zero
 * @dpi: %gdouble, render at this DPI
 * @scale: %gdouble, scale render by this factor
 *
 * Render a PDF file into a VIPS image. Rendering uses the libpoppler library
 * and should be fast. 
 *
 * The output image is always RGBA --- CMYK PDFs will be
 * converted. If you need CMYK bitmaps, you should use vips_magickload()
 * instead.
 *
 * Rendering is progressive, that is, the image is rendered in strips equal in 
 * height to the tile height. If your PDF contains large image files and 
 * they span several strips in the output image, they will be decoded multiple 
 * times. To fix this, increase the the tile height, for example:
 *
 * |[
 * vips copy huge.pdf x.png --vips-tile-height=1024
 * ]|
 *
 * Will process images in 1024-pixel high strips, potentially much faster,
 * though of course also using a lot more memory.
 *
 * Use @page to select a page to render, numbering from zero.
 *
 * Use @dpi to set the rendering resolution. The default is 72. Alternatively,
 * you can scale the rendering from the default 1 point == 1 pixel by 
 * setting @scale.
 *
 * The operation fills a number of header fields with metadata, for example
 * "pdf-author". They may be useful. 
 *
 * This function only reads the image header and does not render any pixel
 * data. Rendering occurs when pixels are accessed.
 *
 * See also: vips_image_new_from_file(), vips_magickload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pdfload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "pdfload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_pdfload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @page: %gint, load this page, numbered from zero
 * @dpi: %gdouble, render at this DPI
 * @scale: %gdouble, scale render by this factor
 *
 * Read a PDF-formatted memory block into a VIPS image. Exactly as
 * vips_pdfload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_pdfload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pdfload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "pdfload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_svgload:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @dpi: %gdouble, render at this DPI
 * @scale: %gdouble, scale render by this factor
 *
 * Render a SVG file into a VIPS image.  Rendering uses the librsvg library
 * and should be fast.
 *
 * Use @dpi to set the rendering resolution. The default is 72. Alternatively,
 * you can scale the rendering from the default 1 point == 1 pixel by @scale.
 *
 * This function only reads the image header and does not render any pixel
 * data. Rendering occurs when pixels are accessed.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_svgload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "svgload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_svgload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @dpi: %gdouble, render at this DPI
 * @scale: %gdouble, scale render by this factor
 *
 * Read a SVG-formatted memory block into a VIPS image. Exactly as
 * vips_svgload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_svgload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_svgload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "svgload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_gifload:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @page: %ginit, page (frame) to read
 *
 * Read a GIF file into a VIPS image.  Rendering uses the giflib library.
 *
 * Use @page to set page number (frame number) to read.
 *
 * The whole GIF is parsed and read into memory on header access, the whole 
 * GIF is rendered on first pixel access.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "gifload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_gifload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @page: %ginit, page (frame) to read
 *
 * Read a GIF-formatted memory block into a VIPS image. Exactly as
 * vips_gifload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_gifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "gifload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}
