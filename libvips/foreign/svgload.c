/* load SVG with librsvg
 *
 * 7/2/16
 * 	- from svgload.c
 * 1/8/16 felixbuenemann
 * 	- add svgz support
 * 18/1/17
 * 	- invalidate operation on read error
 * 8/7/17
 * 	- fix DPI mixup, thanks Fosk
 * 9/9/17
 * 	- limit max tile width to 30k pixels to prevent overflow in render
 * 17/9/17 lovell
 * 	- handle scaling of svg files missing width and height attributes
 * 22/3/18 lovell
 * 	- svgload was missing is_a
 * 28/6/19
 * 	- add "unlimited"
 * 	- requires us to use the gio API to librsvg
 * 11/9/19
 * 	- rework as a sequential loader to reduce overcomputation
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
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#if defined(HAVE_RSVG)

#include <cairo.h>
#include <librsvg/rsvg.h>

/* The <svg tag must appear within this many bytes of the start of the file.
 */
#define SVG_HEADER_SIZE (1000)

/* The maximum pixel width librsvg is able to render.
 */
#define RSVG_MAX_WIDTH (32767)

/* A handy #define for we-will-handle-svgz.
 */
#if LIBRSVG_CHECK_FEATURE(SVGZ) && defined(HAVE_ZLIB)
#define HANDLE_SVGZ
#endif

#ifdef HANDLE_SVGZ
#include <zlib.h>
#endif

typedef struct _VipsForeignLoadSvg {
	VipsForeignLoad parent_object;

	/* Render at this DPI.
	 */
	double dpi;

	/* Calculate this from DPI. At 72 DPI, we render 1:1 with cairo.
	 */
	double scale;

	/* Scale using cairo when SVG has no width and height attributes.
	 */
	double cairo_scale;

	/* Allow SVGs of any size.
	 */
	gboolean unlimited;

	RsvgHandle *page;

} VipsForeignLoadSvg;

typedef VipsForeignLoadClass VipsForeignLoadSvgClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadSvg, vips_foreign_load_svg, 
	VIPS_TYPE_FOREIGN_LOAD );

#ifdef HANDLE_SVGZ
static void *
vips_foreign_load_svg_zalloc( void *opaque, unsigned items, unsigned size )
{
	return( g_malloc0_n( items, size ) );
}

static void
vips_foreign_load_svg_zfree( void *opaque, void *ptr )
{
	return( g_free( ptr ) );
}
#endif /*HANDLE_SVGZ*/

/* This is used by both the file and buffer subclasses.
 */
static gboolean
vips_foreign_load_svg_is_a( const void *buf, size_t len )
{
	char *str;

#ifdef HANDLE_SVGZ
	/* If the buffer looks like a zip, deflate to here and then search
	 * that for <svg.
	 */
	char obuf[SVG_HEADER_SIZE];
#endif /*HANDLE_SVGZ*/

	int i;

	/* Start with str pointing at the argument buffer, swap to it pointing
	 * into obuf if we see zip data.
	 */
	str = (char *) buf;

#ifdef HANDLE_SVGZ
	/* Check for SVGZ gzip signature and inflate.
	 *
	 * Minimum gzip size is 18 bytes, starting with 1F 8B.
	 */
	if( len >= 18 && 
		str[0] == '\037' && 
		str[1] == '\213' ) {
		z_stream zs;
		size_t opos;

		zs.zalloc = (alloc_func) vips_foreign_load_svg_zalloc;
		zs.zfree = (free_func) vips_foreign_load_svg_zfree;
		zs.opaque = Z_NULL;
		zs.next_in = (unsigned char *) str;
		zs.avail_in = len;

		/* There isn't really an error return from is_a_buffer()
		 */
		if( inflateInit2( &zs, 15 | 32 ) != Z_OK ) 
			return( FALSE );

		opos = 0;
		do {
			zs.avail_out = sizeof( obuf ) - opos;
			zs.next_out = (unsigned char *) obuf + opos;
			if( inflate( &zs, Z_NO_FLUSH ) < Z_OK ) {
				inflateEnd( &zs );
				return( FALSE );
			}
			opos = sizeof( obuf ) - zs.avail_out;
		} while( opos < sizeof( obuf ) && 
			zs.avail_in > 0 );

		inflateEnd( &zs );

		str = obuf;
		len = opos;
	}
#endif /*HANDLE_SVGZ*/

	/* SVG documents are very freeform. They normally look like:
	 *
	 * <?xml version="1.0" encoding="UTF-8"?>
	 * <svg xmlns="http://www.w3.org/2000/svg" ...
	 *
	 * But there can be a doctype in there too. And case and whitespace can
	 * vary a lot. And the <?xml can be missing. And you can have a comment
	 * before the <svg line.
	 *
	 * Simple rules:
	 * - first 24 chars are plain ascii (x09-x7F)
	 * - first SVG_HEADER_SIZE chars contain "<svg", upper or lower case.
	 *
	 * We could rsvg_handle_new_from_data() on the buffer, but that can be
	 * horribly slow for large documents. 
	 */
	if( len < 24 )
		return( 0 );
	for( i = 0; i < 24; i++ )
		if( !isascii( str[i] ) || str[i] < 9 )
			return( FALSE );
	for( i = 0; i < SVG_HEADER_SIZE && i < len - 5; i++ )
		if( g_ascii_strncasecmp( str + i, "<svg", 4 ) == 0 )
			return( TRUE );

	return( FALSE );
}

static void
vips_foreign_load_svg_dispose( GObject *gobject )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) gobject;

	VIPS_UNREF( svg->page );

	G_OBJECT_CLASS( vips_foreign_load_svg_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_svg_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static VipsForeignFlags
vips_foreign_load_svg_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static void
vips_foreign_load_svg_parse( VipsForeignLoadSvg *svg, VipsImage *out )
{
	RsvgDimensionData dimensions;
	int width;
	int height;
	double scale;
	double res;

	/* Calculate dimensions at default dpi/scale.
	 */
	rsvg_handle_set_dpi( svg->page, 72.0 );
	rsvg_handle_get_dimensions( svg->page, &dimensions );
	width = dimensions.width;
	height = dimensions.height;

	/* Calculate dimensions at required dpi/scale.
	 */
	scale = svg->scale * svg->dpi / 72.0;
	if( scale != 1.0 ) {
		rsvg_handle_set_dpi( svg->page, svg->dpi * svg->scale );
		rsvg_handle_get_dimensions( svg->page, &dimensions );

		if( width == dimensions.width && 
			height == dimensions.height ) {
			/* SVG without width and height always reports the same 
			 * dimensions regardless of dpi. Apply dpi/scale using 
			 * cairo instead.
			 */
			svg->cairo_scale = scale;
			width = VIPS_ROUND_UINT( width * scale );
			height = VIPS_ROUND_UINT( height * scale );
		} 
		else {
			/* SVG with width and height reports correctly scaled 
			 * dimensions.
			 */
			width = dimensions.width;
			height = dimensions.height;
		}
	}

	/* We need pixels/mm for vips.
	 */
	res = svg->dpi / 25.4;

	vips_image_init_fields( out, 
		width, height,
		4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, res, res );

	/* We render to a linecache, so fat strips work well.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_FATSTRIP, NULL );

}

static int
vips_foreign_load_svg_header( VipsForeignLoad *load )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) load;

	vips_foreign_load_svg_parse( svg, load->out ); 

	return( 0 );
}

static int
vips_foreign_load_svg_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) a;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( svg );
	VipsRect *r = &or->valid;

	cairo_surface_t *surface;
	cairo_t *cr;
	int y;

#ifdef DEBUG
	printf( "vips_foreign_load_svg_generate:\n     "
		"left = %d, top = %d, width = %d, height = %d\n", 
		r->left, r->top, r->width, r->height ); 
#endif /*DEBUG*/

	/* rsvg won't always paint the background.
	 */
	vips_region_black( or ); 

	surface = cairo_image_surface_create_for_data( 
		VIPS_REGION_ADDR( or, r->left, r->top ), 
		CAIRO_FORMAT_ARGB32, 
		r->width, r->height, 
		VIPS_REGION_LSKIP( or ) );
	cr = cairo_create( surface );
	cairo_surface_destroy( surface );

	cairo_scale( cr, svg->cairo_scale, svg->cairo_scale );
	cairo_translate( cr, -r->left / svg->cairo_scale,
		-r->top / svg->cairo_scale );

	/* rsvg is single-threaded, but we don't need to lock since we're
	 * running inside a non-threaded tilecache.
	 */
	if( !rsvg_handle_render_cairo( svg->page, cr ) ) {
		cairo_destroy( cr );
		vips_operation_invalidate( VIPS_OPERATION( svg ) );
		vips_error( class->nickname, 
			"%s", _( "SVG rendering failed" ) );
		return( -1 );
	}

	cairo_destroy( cr );

	/* Cairo makes pre-multipled BRGA -- we must byteswap and unpremultiply.
	 */
	for( y = 0; y < r->height; y++ ) 
                vips__premultiplied_bgra2rgba( 
			(guint32 *) VIPS_REGION_ADDR( or, r->left, r->top + y ),
			r->width ); 

	return( 0 ); 
}

static int
vips_foreign_load_svg_load( VipsForeignLoad *load )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) load, 3 );

	/* librsvg starts to fail if any axis in a single render call is over
	 * RSVG_MAX_WIDTH pixels. vips_sequential() will use a tilecache where 
	 * each tile is a strip the width of the image and (in this case) 
	 * 2000 pixels high. To be able to render images wider than 
	 * RSVG_MAX_WIDTH pixels, we need to chop these strips up.
	 * We use a small tilecache between the seq and our gen to do this.
	 *
	 * Make tiles 2000 pixels high to limit overcomputation. 
	 */
	t[0] = vips_image_new(); 
	vips_foreign_load_svg_parse( svg, t[0] ); 
	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_svg_generate, NULL, svg, NULL ) ||
		vips_tilecache( t[0], &t[1],
			"tile_width", VIPS_MIN( t[0]->Xsize, RSVG_MAX_WIDTH ),
			"tile_height", 2000,
			"max_tiles", 1,
			NULL ) ||
		vips_sequential( t[1], &t[2], 
			"tile_height", 2000, 
			NULL ) ||
		vips_image_write( t[2], load->real ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_svg_class_init( VipsForeignLoadSvgClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_svg_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "svgload_base";
	object_class->description = _( "load SVG with rsvg" );

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -5;

	load_class->get_flags_filename = 
		vips_foreign_load_svg_get_flags_filename;
	load_class->get_flags = vips_foreign_load_svg_get_flags;
	load_class->load = vips_foreign_load_svg_load;

	VIPS_ARG_DOUBLE( class, "dpi", 21,
		_( "DPI" ),
		_( "Render at this DPI" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadSvg, dpi ),
		0.001, 100000.0, 72.0 );

	VIPS_ARG_DOUBLE( class, "scale", 22,
		_( "Scale" ),
		_( "Scale output by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadSvg, scale ),
		0.001, 100000.0, 1.0 );

	VIPS_ARG_BOOL( class, "unlimited", 23,
		_( "Unlimited" ),
		_( "Allow SVG of any size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadSvg, unlimited ),
		FALSE );

}

static void
vips_foreign_load_svg_init( VipsForeignLoadSvg *svg )
{
	svg->dpi = 72.0;
	svg->scale = 1.0;
	svg->cairo_scale = 1.0;
}

typedef struct _VipsForeignLoadSvgSource {
	VipsForeignLoadSvg parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadSvgSource;

typedef VipsForeignLoadClass VipsForeignLoadSvgSourceClass;

G_DEFINE_TYPE( VipsForeignLoadSvgSource, vips_foreign_load_svg_source, 
	vips_foreign_load_svg_get_type() );

gboolean
vips_foreign_load_svg_source_is_a_source( VipsSource *source )
{
	unsigned char *data;
	size_t bytes_read;

	if( (bytes_read = vips_source_sniff_at_most( source, 
		&data, SVG_HEADER_SIZE )) <= 0 )
		return( FALSE );

	return( vips_foreign_load_svg_is_a( data, bytes_read ) );
}

static int
vips_foreign_load_svg_source_header( VipsForeignLoad *load )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) load;
	VipsForeignLoadSvgSource *source = 
		(VipsForeignLoadSvgSource *) load;
	RsvgHandleFlags flags = svg->unlimited ? RSVG_HANDLE_FLAG_UNLIMITED : 0;

	GError *error = NULL;

	GInputStream *gstream;

	if( vips_source_rewind( source->source ) )
		return( -1 );

	gstream = vips_g_input_stream_new_from_source( source->source );
	if( !(svg->page = rsvg_handle_new_from_stream_sync( 
		gstream, NULL, flags, NULL, &error )) ) {
		g_object_unref( gstream );
		vips_g_error( &error );
		return( -1 ); 
	}
	g_object_unref( gstream );

	return( vips_foreign_load_svg_header( load ) );
}

static int
vips_foreign_load_svg_source_load( VipsForeignLoad *load )
{
	VipsForeignLoadSvgSource *source = (VipsForeignLoadSvgSource *) load;

	if( vips_source_rewind( source->source ) ||
		vips_foreign_load_svg_load( load ) ||
		vips_source_decode( source->source ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_svg_source_class_init( VipsForeignLoadSvgSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "svgload_source";
	object_class->description = _( "load svg from source" );

	load_class->is_a_source = vips_foreign_load_svg_source_is_a_source;
	load_class->header = vips_foreign_load_svg_source_header;
	load_class->load = vips_foreign_load_svg_source_load;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadSvgSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_svg_source_init( VipsForeignLoadSvgSource *source )
{
}

typedef struct _VipsForeignLoadSvgFile {
	VipsForeignLoadSvg parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadSvgFile;

typedef VipsForeignLoadSvgClass VipsForeignLoadSvgFileClass;

G_DEFINE_TYPE( VipsForeignLoadSvgFile, vips_foreign_load_svg_file, 
	vips_foreign_load_svg_get_type() );

static gboolean
vips_foreign_load_svg_file_is_a( const char *filename )
{
	unsigned char buf[SVG_HEADER_SIZE];
	guint64 bytes;

	return( (bytes = vips__get_bytes( filename, 
			buf, SVG_HEADER_SIZE )) > 0 &&
		vips_foreign_load_svg_is_a( buf, bytes ) );
}

static int
vips_foreign_load_svg_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) load;
	VipsForeignLoadSvgFile *file = (VipsForeignLoadSvgFile *) load;
	RsvgHandleFlags flags = svg->unlimited ? RSVG_HANDLE_FLAG_UNLIMITED : 0;

	GError *error = NULL;

	GFile *gfile;

	gfile = g_file_new_for_path( file->filename );
	if( !(svg->page = rsvg_handle_new_from_gfile_sync( 
		gfile, flags, NULL, &error )) ) { 
		g_object_unref( gfile );
		vips_g_error( &error );
		return( -1 ); 
	}
	g_object_unref( gfile );

	VIPS_SETSTR( load->out->filename, file->filename );

	return( vips_foreign_load_svg_header( load ) );
}

static const char *vips_foreign_svg_suffs[] = {
	".svg",
	/* librsvg supports svgz directly, no need to check for zlib here.
	 */
#if LIBRSVG_CHECK_FEATURE(SVGZ)
	".svgz",
	".svg.gz",
#endif
	NULL
};

static void
vips_foreign_load_svg_file_class_init( 
	VipsForeignLoadSvgFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "svgload";

	foreign_class->suffs = vips_foreign_svg_suffs;

	load_class->is_a = vips_foreign_load_svg_file_is_a;
	load_class->header = vips_foreign_load_svg_file_header;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadSvgFile, filename ),
		NULL );

}

static void
vips_foreign_load_svg_file_init( VipsForeignLoadSvgFile *file )
{
}

typedef struct _VipsForeignLoadSvgBuffer {
	VipsForeignLoadSvg parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadSvgBuffer;

typedef VipsForeignLoadSvgClass VipsForeignLoadSvgBufferClass;

G_DEFINE_TYPE( VipsForeignLoadSvgBuffer, vips_foreign_load_svg_buffer, 
	vips_foreign_load_svg_get_type() );

static int
vips_foreign_load_svg_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) load;
	VipsForeignLoadSvgBuffer *buffer = 
		(VipsForeignLoadSvgBuffer *) load;
	RsvgHandleFlags flags = svg->unlimited ? RSVG_HANDLE_FLAG_UNLIMITED : 0;

	GError *error = NULL;

	GInputStream *gstream;

	gstream = g_memory_input_stream_new_from_data( 
		buffer->buf->data, buffer->buf->length, NULL );
	if( !(svg->page = rsvg_handle_new_from_stream_sync( 
		gstream, NULL, flags, NULL, &error )) ) { 
		g_object_unref( gstream );
		vips_g_error( &error );
		return( -1 ); 
	}
	g_object_unref( gstream );

	return( vips_foreign_load_svg_header( load ) );
}

static void
vips_foreign_load_svg_buffer_class_init( 
	VipsForeignLoadSvgBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "svgload_buffer";

	load_class->is_a_buffer = vips_foreign_load_svg_is_a;
	load_class->header = vips_foreign_load_svg_buffer_header;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadSvgBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_svg_buffer_init( VipsForeignLoadSvgBuffer *buffer )
{
}

#endif /*HAVE_RSVG*/

/**
 * vips_svgload:
 * @filename: file to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dpi: %gdouble, render at this DPI
 * * @scale: %gdouble, scale render by this factor
 * * @unlimited: %gboolean, allow SVGs of any size
 *
 * Render a SVG file into a VIPS image.  Rendering uses the librsvg library
 * and should be fast.
 *
 * Use @dpi to set the rendering resolution. The default is 72. You can also
 * scale the rendering by @scale. 
 *
 * This function only reads the image header and does not render any pixel
 * data. Rendering occurs when pixels are accessed.
 *
 * SVGs larger than 10MB are normally blocked for security. Set @unlimited to
 * allow SVGs of any size.
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
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dpi: %gdouble, render at this DPI
 * * @scale: %gdouble, scale render by this factor
 * * @unlimited: %gboolean, allow SVGs of any size
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
 * vips_svgload_source:
 * @source: source to load from
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_svgload(), but read from a source. 
 *
 * See also: vips_svgload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_svgload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "svgload_source", ap, source, out );
	va_end( ap );

	return( result );
}

