/* VIPS function dispatch tables for image file load/save.
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

/**
 * SECTION: file
 * @short_description: load and save in a variety of files
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * VIPS has a simple system for representing image load and save operations in
 * a generic way.
 *
 * You can ask for a loader for a certain file or select a saver based on a
 * filename. Once you have found a file, you can use it to load a file of
 * that type, save an image to a file of that type, query files for their type
 * and fields, and ask for supported features. You can also call the
 * converters directly, if you like. 
 *
 * If you define a new file, support for
 * it automatically appears in all VIPS user-interfaces. It will also be
 * transparently supported by vips_image_new_from_file() and friends.
 *
 * VIPS comes with VipsFile for TIFF, JPEG, PNG, Analyze, PPM, OpenEXR, CSV,
 * Matlab, Radiance, RAW, VIPS and one that wraps libMagick. 
 */

/**
 * VipsFileFlags: 
 * @VIPS_FILE_NONE: no flags set
 * @VIPS_FILE_PARTIAL: the image may be read lazilly
 * @VIPS_FILE_BIGENDIAN: image pixels are most-significant byte first
 *
 * Some hints about the image loader.
 *
 * @VIPS_FILE_PARTIAL means that the image can be read directly from the
 * file without needing to be unpacked to a temporary image first. 
 *
 * @VIPS_FILE_BIGENDIAN means that image pixels are most-significant byte
 * first. Depending on the native byte order of the host machine, you may
 * need to swap bytes. See copy_swap().
 */

/**
 * VipsFile:
 *
 * #VipsFile has these virtual methods:
 *
 * |[
 * typedef struct _VipsFileClass {
 *   VipsObjectClass parent_class;
 *
 *   gboolean (*is_a)( const char *filename );
 *   int (*header)( const char *filename, VipsImage *out );
 *   int (*load)( const char *filename, VipsImage *out );
 *   int (*save)( VipsImage *in, const char *filename );
 *   VipsFileFlags (*get_flags)( const char *filename );
 *   int priority;
 *   const char **suffs;
 * } VipsFileClass;
 * ]|
 *
 * Add a new file to VIPS by subclassing VipsFile. Subclasses need to 
 * implement at least load() or save(). 
 *
 * These members are:
 *
 * <itemizedlist>
 *   <listitem>
 *     <para>
 * is_a() This function should return %TRUE if the file 
 * contains an image of this type. If you don't define this function, VIPS
 * will use the list of suffixes you supply instead.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * header() This function should load the image header,
 * but not load any pixel data. If you don't define it, VIPS will use your
 * load() method instead. Return 0 for success, -1 for error, setting
 * vips_error().
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * load() This function should load the image, or perhaps use 
 * vips_image_generate() to
 * attach something to load sections of the image on demand. 
 * Users can embed
 * load options in the filename, see (for example) im_jpeg2vips().
 * If you don't
 * define this method, you can still define save() and have a save-only
 * file.
 * Return 0 for success, -1 for error, setting
 * im_error().
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * save() This function should save the image to the file. 
 * Users can embed
 * save options in the filename, see (for example) im_vips2tiff().
 * If you don't
 * define this method, you can still define load() and have a load-only
 * file.
 * Return 0 for success, -1 for error, setting
 * im_error().
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * get_flags() This function should return a hint about the properties of this
 * loader on this file. If you don't define it, users will always see '0', or
 * no flags. 
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <structfield>priority</structfield> Where this file should fit in this 
 * list of
 * supported files. 0 is a sensible value for most files. Set a negative
 * value if you want to be lower on the list, positive to move up.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <structfield>suffs</structfield> A %NULL-terminated list of possible file 
 * name
 * suffixes, for example:
 * |[
 * static const char *tiff_suffs[] = { ".tif", ".tiff", NULL };
 * ]|
 * The suffix list is used to select a file to save a file in, and to pick a
 * loader if you don't define is_a().
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * You should also define <structfield>nickname</structfield> and
 * <structfield>description</structfield> in #VipsObject. 
 *
 * At the command-line, use:
 *
 * |[
 * vips --list classes | grep File
 * ]|
 *
 * To see a list of all the supported files.
 *
 * For example, the TIFF file is defined like this:
 *
|[
typedef VipsFile VipsFileTiff;
typedef VipsFileClass VipsFileTiffClass;

static void
vips_file_tiff_class_init( VipsFileTiffClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFileClass *file_class = (VipsFileClass *) class;

	object_class->nickname = "tiff";
	object_class->description = _( "TIFF" );

	file_class->is_a = istiff;
	file_class->header = tiff2vips_header;
	file_class->load = im_tiff2vips;
	file_class->save = im_vips2tiff;
	file_class->get_flags = tiff_flags;
	file_class->suffs = tiff_suffs;
}

static void
vips_file_tiff_init( VipsFileTiff *object )
{
}

G_DEFINE_TYPE( VipsFileTiff, vips_file_tiff, VIPS_TYPE_FILE );
]|
 *
 * Then call vips_file_tiff_get_type() somewhere in your init code to link
 * the file into VIPS (though of course the tiff file is linked in for you
 * already).
 *
 */

/* To iterate over supported files, we build a temp list of subclasses of 
 * VipsFile, sort by priority, iterate, and free.
 */

static void *
file_add_class( VipsFileClass *file, GSList **files )
{
	/* Append so we don't reverse the list of files.
	 */
	*files = g_slist_append( *files, file );

	return( NULL );
}

static gint
file_compare( VipsFileClass *a, VipsFileClass *b )
{
        return( b->priority - a->priority );
}

/**
 * vips_file_map:
 * @base: base class to search below (eg. "VipsFileLoad")
 * @fn: function to apply to each #VipsFileClass
 * @a: user data
 * @b: user data
 *
 * Apply a function to every #VipsFileClass that VIPS knows about. Files
 * are presented to the function in priority order. 
 *
 * Like all VIPS map functions, if @fn returns %NULL, iteration continues. If
 * it returns non-%NULL, iteration terminates and that value is returned. The
 * map function returns %NULL if all calls return %NULL.
 *
 * See also: vips_slist_map().
 *
 * Returns: the result of iteration
 */
void *
vips_file_map( const char *base, VipsSListMap2Fn fn, void *a, void *b )
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

/* Abstract base class for image files.
 */

G_DEFINE_ABSTRACT_TYPE( VipsFile, vips_file, VIPS_TYPE_OPERATION );

static void
vips_file_print_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsFileClass *class = VIPS_FILE_CLASS( object_class );
	const char **p;

	VIPS_OBJECT_CLASS( vips_file_parent_class )->
		print_class( object_class, buf );
	vips_buf_appends( buf, ", " );

	if( class->suffs ) {
		vips_buf_appends( buf, "(" );
		for( p = class->suffs; *p; p++ ) {
			vips_buf_appendf( buf, "%s", *p );
			if( p[1] )
				vips_buf_appends( buf, ", " );
		}
		vips_buf_appends( buf, ") " );
	}

	vips_buf_appends( buf, "priority=%d ", class->priority );

	if( class->is_a )
		vips_buf_appends( buf, "is_a " );
}

static void
vips_file_class_init( VipsFileClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "file";
	object_class->description = _( "file file support" );
	object_class->print_class = vips_file_print_class;

	VIPS_ARG_STRING( class, "filename", 12, 
		_( "Filename" ),
		_( "File filename" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsFile, filename ),
		NULL );
}

static void
vips_file_init( VipsFile *object )
{
}

/* Abstract base class for image load.
 */

G_DEFINE_ABSTRACT_TYPE( VipsFileLoad, vips_files_load, VIPS_TYPE_FILE );

static void
vips_file_load_print_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsFileLoadClass *class = VIPS_FILE_LOAD_CLASS( object_class );
	const char **p;

	VIPS_OBJECT_CLASS( vips_file_load_parent_class )->
		print_class( object_class, buf );
	vips_buf_appends( buf, ", " );

	if( class->header )
		vips_buf_appends( buf, "header " );
	if( class->load )
		vips_buf_appends( buf, "load " );
	if( class->get_flags )
		vips_buf_appends( buf, "get_flags " );
}

static int
vips_file_load_build( VipsObject *object )
{
	VipsFile *file = VIPS_FILE( object );
	VipsFileLoad *load = VIPS_FILE_LOAD( object );

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_file_load_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_file_load_class_init( VipsFileLoadClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "fileload";
	object_class->description = _( "file loaders" );
	object_class->print_class = vips_file_load_print_class;
	object_class->build = vips_file_load_build;

	VIPS_ARG_ENUM( class, "flags", 6, 
		_( "Flags" ), 
		_( "Flags for this file" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsFileLoad, flags ),
		VIPS_TYPE_FILE_FLAGS, VIPS_FILE_NONE ); 

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsFileLoad, out ) );

}

static void
vips_file_load_init( VipsFileLoad *object )
{
}

/* Can this file open this file?
 */
static void *
vips_file_load_new_from_file_sub( VipsFileLoadClass *load_class, 
	const char *filename )
{
	if( load_class->is_a ) {
		if( load_class->is_a( filename ) ) 
			return( load_class );
	}
	else if( vips_filename_suffix_match( filename, load_class->suffs ) )
		return( load_class );

	return( NULL );
}

/**
 * vips_file_load_new_from_file:
 * @filename: file to find a file for
 *
 * Searches for a file you could use to load a file. Set some more options
 * after this, then call _build() to actually load in the file.
 *
 * See also: vips_file_read(), vips_file_for_name().
 *
 * Returns: a file on success, %NULL on error
 */
VipsFileLoad *
vips_file_load_new_from_file( const char *filename )
{
	VipsFileLoadClass *load_class;
	VipsFileLoad *load;

	if( !vips_existsf( "%s", filename ) ) {
		vips_error( "VipsFileLoad", 
			_( "file \"%s\" not found" ), filename );
		return( NULL );
	}

	if( !(load_class = (VipsFileLoadClass *) vips_file_map( 
		"VipsFileLoad",
		(VipsSListMap2Fn) vips_file_load_new_from_file_sub, 
		(void *) filename, NULL )) ) {
		vips_error( "VipsFileLoad", 
			_( "file \"%s\" not a known file" ), name );
		return( NULL );
	}

	load = VIPS_FILE_LOAD( 
		g_object_new( G_TYPE_FROM_CLASS( load_class ), NULL ) );

	/* May as well set flags here, should be quick.
	 */
	if( load_class->get_flags )
		g_object_set( load,
			"flags", load_class->get_flags( load ),
			NULL );

	return( load );
}

/* Abstract base class for image savers.
 */

G_DEFINE_ABSTRACT_TYPE( VipsFileSave, vips_file_save, VIPS_TYPE_FILE );

static void
vips_file_save_print_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsFileSaveClass *class = VIPS_FILE_SAVE_CLASS( object_class );
	const char **p;

	VIPS_OBJECT_CLASS( vips_file_save_parent_class )->
		print_class( object_class, buf );
	vips_buf_appends( buf, ", " );

	if( class->save )
		vips_buf_appends( buf, "save " );
}

static int
vips_file_save_build( VipsObject *object )
{
	VipsFile *file = VIPS_FILE( object );
	VipsFileSave *save = VIPS_FILE_SAVE( object );

	if( VIPS_OBJECT_CLASS( vips_file_save_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_file_save_class_init( VipsFileSaveClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "filesave";
	object_class->description = _( "file savers" );
	object_class->print_class = vips_file_save_print_class;
	object_class->build = vips_file_save_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Image to save" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFileSave, in ) );
}

static void
vips_file_save_init( VipsFile *object )
{
}

/* Can we write this filename with this file? 
 */
static void *
vips_file_save_new_from_filename_sub( VipsFileSaveClass *save_class, 
	const char *filename )
{
	VipsFileClass *file = VIPS_FILE_CLASS( save_class );

	if( save_class->save &&
		vips_filename_suffix_match( filename, file->suffs ) )
		return( save_class );

	return( NULL );
}

/**
 * vips_file_save_new_from_filename:
 * @filename: name to find a file for
 *
 * Searches for a file you could use to save a file.
 *
 * See also: vips_file_write(), vips_file_for_file().
 *
 * Returns: a file on success, %NULL on error
 */
VipsFileSave *
vips_file_save_new_from_filename( const char *filename )
{
	VipsFileSaveClass *save_class;
	VipsFileSave *save;

	if( !(save_class = (VipsFileSaveClass *) vips_file_map( 
		"VipsFileSave",
		(VipsSListMap2Fn) vips_file_save_new_from_filename_sub, 
		(void *) filename, NULL )) ) {
		vips_error( "VipsFileSave",
			_( "\"%s\" is not a supported image file." ), 
			filename );

		return( NULL );
	}

	save = VIPS_FILE_SAVE( 
		g_object_new( G_TYPE_FROM_CLASS( save_class ), NULL ) );

	return( save );
}

/**
 * vips_file_read:
 * @filename: file to load
 * @out: write the file to this image
 *
 * Searches for a file for this file, then loads the file into @out.
 *
 * See also: vips_file_write().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_file_read( const char *filename, VipsImage *out )
{
	VipsFileLoad *load;

	if( !(load = vips_file_load_new_from_file( filename )) )
		return( -1 );
	g_object_unref( load );

	return( 0 );
}

/**
 * vips_file_write:
 * @in: image to write
 * @filename: file to write to
 *
 * Searches for a file for this name, then saves @im to it.
 *
 * See also: vips_file_read().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_file_write( VipsImage *in, const char *filename )
{
	VipsFileClass *file;

	if( !(file = vips_file_for_name( filename )) || 
		file->save( in, filename ) ) 
		return( -1 );

	return( 0 );
}

