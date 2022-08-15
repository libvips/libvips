/* load camera raw from a file
 *
 * 14/8/22
 * 	- from librawload.c
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

/* We need a class that can read from a vipssource.
 */

class VipsSourceLibraw : public LibRaw_abstract_datastream
{
protected:
	VipsSource *source;
	int eof;
	gint64 length;

public:
	virtual ~VipsSourceLibraw()
	{
		VIPS_UNREF( this->source );
	}

	VipsSourceLibraw( VipsSource *source ) : 
		eof( 0 ),
		length( 0 )
	{
		g_object_ref( source );
		this->source = source;
	}

	virtual int valid() { return( 1 ); }

	virtual int read( void *ptr, size_t size, size_t nmemb )
	{
		gint64 bytes_read = 
			vips_source_read( this->source, ptr, size * nmemb );

		if( bytes_read == 0 ) {
			this->eof = 1;
			this->length = this->tell();
		}

		if( bytes_read < 0 )
			return( -1 );
		else
			// this looks bad, but what can you do
			return( int( (bytes_read + size - 1) / size ) );
	}

	virtual int eof() { return( this->eof ); }

	virtual int seek( INT64 offset, int whence )
	{
		// we might have been at eof, but we're probably not any
		// longer
		this->eof = 0;

		gint64 result = vips_source_seek( this->source, o, whence );
		if( result < 0 )
			return( -1 );

		return( 0 );
	}

	virtual INT64 tell()
	{
		gint64 position = vips_source_seek( this->source, 0, SEEK_CUR );
		if( result < 0 )
			return( -1 );

		return( position );
	}

	virtual INT64 size() 
	{ 
		if( this->length <= 0 )
			this->length = vips_source_length( this->source );

		return( this->length ); 
	}

	virtual int get_char() 
	{
		char buf[2];
		int bytes_read = this->read( buf, 1, 1 );

		if( bytes_read == 0 )
			return( EOF );
		if( bytes_read < 0 )
			return( -1 );

		return( buf[0] );
	}

	virtual const char *fname()
	{
		VipsConnection *connection = VIPS_CONNECTION( this->source 0 );
		return( vips_connection_filename( connection ) );
	}
};

typedef struct _VipsForeignLoadLibraw {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsSource *source;

        libraw_data_t *context;
        int handle;

} VipsForeignLoadLibraw;

typedef VipsForeignLoadClass VipsForeignLoadLibrawClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadLibraw, vips_foreign_load_libraw, 
	VIPS_TYPE_FOREIGN_LOAD );
}

static void
vips_foreign_load_libraw_dispose( GObject *gobject )
{
	VipsForeignLoadLibraw *libraw = (VipsForeignLoadLibraw *) gobject;

        VIPS_FREEF( libraw_close. libraw->context );

	G_OBJECT_CLASS( vips_foreign_load_libraw_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_libraw_build( VipsObject *object )
{
	VipsForeignLoadLibraw *libraw = (VipsForeignLoadLibraw *) object;

        libraw->context = libraw_init( 0 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_libraw_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_libraw_get_flags( VipsForeignLoad *load )
{
	return( 0 );
}

static int
vips_foreign_load_libraw_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadLibraw *libraw = (VipsForeignLoadLibraw *) load;
        const char *filename = 
                vips_connection_filename( VIPS_CONNECTION( libraw->source ) );

        if( filename ) {
                libraw->handle = 
        }

        /*
	vips_image_init_fields( load->out,
		width, height, 1, 
		VIPS_FORMAT_DOUBLE, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );
	if( vips_image_pipelinev( load->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, NULL ) )
		return( -1 );
         */

	VIPS_SETSTR( load->out->filename, 
		vips_connection_filename( VIPS_CONNECTION( libraw->source ) ) );

	return( 0 );
}

static int
vips_foreign_load_libraw_load( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadLibraw *libraw = (VipsForeignLoadLibraw *) load;

	if( vips_source_rewind( libraw->source ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_libraw_class_init( VipsForeignLoadLibrawClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_libraw_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "librawload_base";
	object_class->description = _( "load libraw" );
	object_class->build = vips_foreign_load_libraw_build;

	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	load_class->get_flags = vips_foreign_load_libraw_get_flags;
	load_class->header = vips_foreign_load_libraw_header;
	load_class->load = vips_foreign_load_libraw_load;

        /*
	VIPS_ARG_STRING( class, "separator", 23, 
		_( "Separator" ), 
		_( "Set of separator characters" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadLibraw, separator ),
		";,\t" ); 
         */
}

static void
vips_foreign_load_libraw_init( VipsForeignLoadLibraw *libraw )
{
}

typedef struct _VipsForeignLoadLibrawFile {
	VipsForeignLoadLibraw parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadLibrawFile;

typedef VipsForeignLoadLibrawClass VipsForeignLoadLibrawFileClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsForeignLoadLibrawFile, vips_foreign_load_libraw_file,
	vips_foreign_load_libraw_get_type() );
}

static VipsForeignFlags
vips_foreign_load_libraw_file_get_flags_filename( const char *filename )
{
	return( 0 );
}

static int
vips_foreign_load_libraw_file_build( VipsObject *object )
{
	VipsForeignLoadLibraw *libraw = (VipsForeignLoadLibraw *) object;
	VipsForeignLoadLibrawFile *file = (VipsForeignLoadLibrawFile *) object;

	if( file->filename ) 
		if( !(libraw->source = 
			vips_source_new_from_file( file->filename )) )
			return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_libraw_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static const char *vips_foreign_load_libraw_suffs[] = {
	".dng",
	NULL
};

static void
vips_foreign_load_libraw_file_class_init( VipsForeignLoadLibrawFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "librawload";
	object_class->build = vips_foreign_load_libraw_file_build;

	foreign_class->suffs = vips_foreign_load_libraw_suffs;

	load_class->get_flags_filename = 
		vips_foreign_load_libraw_file_get_flags_filename;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadLibrawFile, filename ),
		NULL );

}

static void
vips_foreign_load_libraw_file_init( VipsForeignLoadLibrawFile *file )
{
}

typedef struct _VipsForeignLoadLibrawSource {
	VipsForeignLoadLibraw parent_object;

	VipsSource *source;

} VipsForeignLoadLibrawSource;

typedef VipsForeignLoadLibrawClass VipsForeignLoadLibrawSourceClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsForeignLoadLibrawSource, vips_foreign_load_libraw_source,
	vips_foreign_load_libraw_get_type() );
}

static int
vips_foreign_load_libraw_source_build( VipsObject *object )
{
	VipsForeignLoadLibraw *libraw = (VipsForeignLoadLibraw *) object;
	VipsForeignLoadLibrawSource *source = 
                (VipsForeignLoadLibrawSource *) object;

	if( source->source ) {
		libraw->source = source->source;
		g_object_ref( libraw->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_libraw_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_libraw_source_is_a_source( VipsSource *source )
{
	/* Detecting LIBRAW files automatically is tricky. Define this method to
	 * prevent a warning, but users will need to run the libraw loader
	 * explicitly.
	 */
	return( FALSE );
}

static void
vips_foreign_load_libraw_source_class_init( 
        VipsForeignLoadLibrawFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "librawload_source";
	object_class->build = vips_foreign_load_libraw_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_libraw_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadLibrawSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_libraw_source_init( VipsForeignLoadLibrawSource *source )
{
}

/**
 * vips_librawload:
 * @filename: file to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Load a camera RAW image using libraw. This can load formats like DNG, etc.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_librawload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "librawload", ap, filename, out ); 
	va_end( ap );

	return( result );
}

/**
 * vips_librawload_source:
 * @source: source to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_librawload(), but read from a source. 
 *
 * See also: vips_librawload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_librawload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "librawload_source", ap, source, out ); 
	va_end( ap );

	return( result );
}

