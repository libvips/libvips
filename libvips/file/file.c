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
#include <vips/debug.h>

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

	vips_buf_appendf( buf, "priority=%d", class->priority );

}

static void
vips_file_class_init( VipsFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "file";
	object_class->description = _( "load and save image files" );
	object_class->print_class = vips_file_print_class;

	VIPS_ARG_STRING( class, "filename", 1, 
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

/* To iterate over supported files we build a temp list of subclasses of 
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

/* Abstract base class for image load.
 */

G_DEFINE_ABSTRACT_TYPE( VipsFileLoad, vips_file_load, VIPS_TYPE_FILE );

static void
vips_file_load_dispose( GObject *gobject )
{
	VipsFileLoad *load = VIPS_FILE_LOAD( gobject );

	VIPS_UNREF( load->real );

	G_OBJECT_CLASS( vips_file_load_parent_class )->dispose( gobject );
}

static void
vips_file_load_print_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsFileLoadClass *class = VIPS_FILE_LOAD_CLASS( object_class );

	VIPS_OBJECT_CLASS( vips_file_load_parent_class )->
		print_class( object_class, buf );

	if( class->is_a )
		vips_buf_appends( buf, ", is_a" );
	if( class->get_flags )
		vips_buf_appends( buf, ", get_flags" );
	if( class->header )
		vips_buf_appends( buf, ", header" );
	if( class->load )
		vips_buf_appends( buf, ", load" );
}

static size_t
vips_get_disc_threshold( void )
{
	static gboolean done = FALSE;
	static size_t threshold;

	if( !done ) {
		const char *env;

		done = TRUE;

		/* 100mb default.
		 */
		threshold = 100 * 1024 * 1024;

		if( (env = g_getenv( "IM_DISC_THRESHOLD" )) ) 
			threshold = vips__parse_size( env );

		if( vips__disc_threshold ) 
			threshold = vips__parse_size( vips__disc_threshold );

		VIPS_DEBUG_MSG( "vips_get_disc_threshold: "
			"%zd bytes\n", threshold );
	}

	return( threshold );
}

/* Our start function ... do the lazy open, if necessary, and return a region
 * on the new image.
 */
static void *
vips_file_load_start_cb( VipsImage *out, void *a, void *dummy )
{
	VipsFileLoad *load = VIPS_FILE_LOAD( a );
	VipsFileLoadClass *class = VIPS_FILE_LOAD_GET_CLASS( a );

	if( !load->real ) {
		const size_t disc_threshold = vips_get_disc_threshold();
		const size_t image_size = VIPS_IMAGE_SIZEOF_IMAGE( load->out );

		/* We open via disc if:
		 * - 'disc' is set
		 * - disc-threshold has not been set to zero
		 * - the format does not support lazy read
		 * - the uncompressed image will be larger than 
		 *   vips_get_disc_threshold()
		 */
		if( load->disc && 
			disc_threshold && 
			(load->flags & VIPS_FORMAT_PARTIAL) &&
			image_size > disc_threshold ) 
			if( !(load->real = vips_image_new_disc_temp( "%s.v" )) )
				return( NULL );

		/* Otherwise, fall back to a "p".
		 */
		if( !load->real && 
			!(load->real = vips_image_new()) )
			return( NULL );

		/* Read the image in.
		 */
		if( class->load( load ) ||
			vips_image_pio_input( load->real ) ) {
			VIPS_UNREF( load->real );
			return( NULL );
		}
	}

	return( vips_region_new( load->real ) );
}

/* Just pointer-copy.
 */
static int
vips_file_load_generate_cb( VipsRegion *or, 
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
vips_file_load_build( VipsObject *object )
{
	VipsFileLoad *load = VIPS_FILE_LOAD( object );
	VipsFileLoadClass *class = VIPS_FILE_LOAD_GET_CLASS( object );

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( class->get_flags &&
		class->get_flags( load ) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_file_load_parent_class )->
		build( object ) )
		return( -1 );

	/* Read header fields to init the return image. THINSTRIP since this is
	 * probably a disc file. We can't tell yet whether we will be opening
	 * to memory, sadly, so we can't suggest ANY.
	 */
	if( class->header &&
		class->header( load ) )
		return( -1 );
	vips_demand_hint( load->out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	/* Then 'start' creates the real image and 'gen' fetches pixels for 
	 * 'out' from real on demand.
	 */
	if( vips_image_generate( load->out, 
		vips_file_load_start_cb, 
		vips_file_load_generate_cb, 
		vips_stop_one, 
		load, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_file_load_class_init( VipsFileLoadClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->dispose = vips_file_load_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "fileload";
	object_class->description = _( "file loaders" );
	object_class->print_class = vips_file_load_print_class;
	object_class->build = vips_file_load_build;

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsFileLoad, out ) );

	VIPS_ARG_ENUM( class, "flags", 6, 
		_( "Flags" ), 
		_( "Flags for this file" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsFileLoad, flags ),
		VIPS_TYPE_FILE_FLAGS, VIPS_FILE_NONE ); 

	VIPS_ARG_BOOL( class, "disc", 7, 
		_( "Disc" ), 
		_( "Open to disc" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFileLoad, disc ),
		TRUE );

}

static void
vips_file_load_init( VipsFileLoad *load )
{
	load->disc = TRUE;
}

/* Can this file open this file?
 */
static void *
vips_file_load_new_from_file_sub( VipsFileLoadClass *load_class, 
	const char *filename )
{
	VipsFileClass *class = VIPS_FILE_CLASS( load_class );

	if( load_class->is_a ) {
		if( load_class->is_a( filename ) ) 
			return( load_class );
	}
	else if( vips_filename_suffix_match( filename, class->suffs ) )
		return( load_class );

	return( NULL );
}

/**
 * vips_file_find_load:
 * @filename: file to find a file for
 *
 * Searches for an operation you could use to load a file. 
 *
 * See also: vips_file_read().
 *
 * Returns: the nmae of an operation on success, %NULL on error
 */
const char *
vips_file_find_load( const char *filename )
{
	VipsFileLoadClass *load_class;

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
			_( "file \"%s\" not a known file" ), filename );
		return( NULL );
	}

	return( G_OBJECT_CLASS_NAME( load_class ) );
}

/* Abstract base class for image savers.
 */

G_DEFINE_ABSTRACT_TYPE( VipsFileSave, vips_file_save, VIPS_TYPE_FILE );

static void
vips_file_save_dispose( GObject *gobject )
{
	VipsFileSave *save = VIPS_FILE_SAVE( gobject );

	VIPS_UNREF( save->ready );

	G_OBJECT_CLASS( vips_file_save_parent_class )->dispose( gobject );
}

static void
vips_file_save_print_class( VipsObjectClass *object_class, VipsBuf *buf )
{
	VipsFileSaveClass *class = VIPS_FILE_SAVE_CLASS( object_class );

	VIPS_OBJECT_CLASS( vips_file_save_parent_class )->
		print_class( object_class, buf );

	vips_buf_appendf( buf, ", %s", 
		VIPS_ENUM_NICK( VIPS_TYPE_SAVEABLE, class->saveable ) );
}

/* Generate the saveable image.
 */
static int
vips_file_convert_saveable( VipsFileSave *save )
{
	VipsFileSaveClass *class = VIPS_FILE_SAVE_GET_CLASS( save );
	VipsImage *in = save->in;

	/* in holds a reference to the output of our chain as we build it.
	 */
	g_object_ref( in );

	/* If this is an VIPS_CODING_LABQ, we can go straight to RGB.
	 */
	if( in->Coding == VIPS_CODING_LABQ ) {
		VipsImage *out;

		if( vips_LabQ2disp( in, &out, im_col_displays( 7 ), NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	/* If this is an VIPS_CODING_RAD, we go to float RGB or XYZ. We should
	 * probably un-gamma-correct the RGB :(
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

	/* Get the bands right. 
	 */
	if( in->Coding == VIPS_CODING_NONE ) {
		if( in->Bands == 2 && 
			class->saveable != VIPS_SAVEABLE_RGBA ) {
			VipsImage *out;

			if( vips_extract_band( in, &out, 0, NULL ) ) {
				g_object_unref( in );
				return( -1 );
			}
			g_object_unref( in );

			in = out;
		}
		else if( in->Bands > 3 && 
			class->saveable == VIPS_SAVEABLE_RGB ) {
			VipsImage *out;

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
			(class->saveable == VIPS_SAVEABLE_RGB_CMYK || 
			 class->saveable == VIPS_SAVEABLE_RGBA) ) {
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

		/* Else we have VIPS_SAVEABLE_ANY and we don't chop bands down.
		 */
	}

	/* Interpret the Type field for colorimetric images.
	 */
	if( in->Bands == 3 && 
		in->BandFmt == VIPS_FORMAT_SHORT && 
		in->Type == VIPS_INTERPRETATION_LABS ) {
		VipsImage *out;

		if( vips_LabS2LabQ( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	if( in->Coding == VIPS_CODING_LABQ ) {
		VipsImage *out;

		if( vips_LabQ2Lab( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	if( in->Coding != VIPS_CODING_NONE ) {
		g_object_unref( in );
		return( -1 );
	}

	if( in->Bands == 3 && 
		in->Type == VIPS_INTERPRETATION_LCH ) {
		VipsImage *out;

                if( vips_LCh2Lab( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	if( in->Bands == 3 && 
		in->Type == VIPS_INTERPRETATION_YXY ) {
		VipsImage *out;

                if( vips_Yxy2Lab( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	if( in->Bands == 3 && 
		in->Type == VIPS_INTERPRETATION_UCS ) {
		VipsImage *out;

                if( vips_UCS2XYZ( in, &out, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
	}

	if( in->Bands == 3 && 
		in->Type == VIPS_INTERPRETATION_LAB ) {
		VipsImage *out;

		if( vips_XYZ2disp( in, &out, im_col_displays( 7 ), NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );

		in = out;
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

	VIPS_UNREF( save->ready );
	save->ready = in;

	return( 0 );
}

static int
vips_file_save_build( VipsObject *object )
{
	VipsFileSave *save = VIPS_FILE_SAVE( object );
	/*
	VipsFile *file = VIPS_FILE( object );
 	 */

	if( vips_file_convert_saveable( save ) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_file_save_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_file_save_class_init( VipsFileSaveClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->dispose = vips_file_save_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "filesave";
	object_class->description = _( "file savers" );
	object_class->print_class = vips_file_save_print_class;
	object_class->build = vips_file_save_build;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Image to save" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFileSave, in ) );
}

static void
vips_file_save_init( VipsFileSave *object )
{
}

/* Can we write this filename with this file? 
 */
static void *
vips_file_save_new_from_filename_sub( VipsFileSaveClass *save_class, 
	const char *filename )
{
	VipsFileClass *class = VIPS_FILE_CLASS( save_class );

	if( vips_filename_suffix_match( filename, class->suffs ) )
		return( save_class );

	return( NULL );
}

/**
 * vips_file_find_save:
 * @filename: name to find a file for
 *
 * Searches for an operation you could use to save a file.
 *
 * See also: vips_file_write().
 *
 * Returns: the name of an operation on success, %NULL on error
 */
const char *
vips_file_find_save( const char *filename )
{
	VipsFileSaveClass *save_class;

	if( !(save_class = (VipsFileSaveClass *) vips_file_map( 
		"VipsFileSave",
		(VipsSListMap2Fn) vips_file_save_new_from_filename_sub, 
		(void *) filename, NULL )) ) {
		vips_error( "VipsFileSave",
			_( "\"%s\" is not a supported image file." ), 
			filename );

		return( NULL );
	}

	return( G_OBJECT_CLASS_NAME( save_class ) );
}

/**
 * vips_file_read:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Loads @filename into @out using the loader recommended by
 * vips_file_find_load().
 *
 * See also: vips_file_write().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_file_read( const char *filename, VipsImage **out, ... )
{
	const char *operation;
	va_list ap;
	int result;

	if( !(operation = vips_file_find_load( filename )) )
		return( -1 );

	va_start( ap, out );
	result = vips_call_split( operation, ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_file_write:
 * @in: image to write
 * @filename: file to write to
 *
 * Saves @in to @filename using the saver recommended by
 * vips_file_find_save().
 *
 * See also: vips_file_read().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_file_write( VipsImage *in, const char *filename, ... )
{
	const char *operation;
	va_list ap;
	int result;

	if( !(operation = vips_file_find_save( filename )) )
		return( -1 );

	va_start( ap, filename );
	result = vips_call_split( operation, ap, in, filename );
	va_end( ap );

	return( result );
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_file_operation_init( void )
{
	extern GType vips_file_load_jpeg_get_type( void ); 
	extern GType vips_file_save_jpeg_get_type( void ); 

#ifdef HAVE_JPEG
	vips_file_load_jpeg_get_type(); 
	vips_file_save_jpeg_get_type(); 
#endif /*HAVE_JPEG*/
}
