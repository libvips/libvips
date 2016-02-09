/* load SVG with librsvg
 *
 * 7/2/16
 * 	- from svgload.c
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

#ifdef HAVE_RSVG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include <cairo.h>
#include <librsvg/rsvg.h>

typedef struct _VipsForeignLoadSvg {
	VipsForeignLoad parent_object;

	/* Render at this DPI.
	 */
	double dpi;

	/* Calculate this from DPI. At 72 DPI, we render 1:1 with cairo.
	 */
	double scale;

	RsvgHandle *page;

} VipsForeignLoadSvg;

typedef VipsForeignLoadClass VipsForeignLoadSvgClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadSvg, vips_foreign_load_svg, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_svg_dispose( GObject *gobject )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) gobject;

	VIPS_UNREF( svg->page );

	G_OBJECT_CLASS( vips_foreign_load_svg_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_svg_build( VipsObject *object )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) object;

	if( !vips_object_argument_isset( object, "scale" ) )
		svg->scale = svg->dpi / 72.0;

	if( VIPS_OBJECT_CLASS( vips_foreign_load_svg_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_svg_get_flags_filename( const char *filename )
{
	/* We can render any part of the page on demand.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_svg_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static void
vips_foreign_load_svg_parse( VipsForeignLoadSvg *svg, 
	VipsImage *out )
{
	RsvgDimensionData dimensions;
	double res;

	rsvg_handle_get_dimensions( svg->page, &dimensions ); 

	/* We need pixels/mm for vips.
	 */
	res = svg->dpi / 25.4;

	vips_image_init_fields( out, 
		dimensions.width * svg->scale, dimensions.height * svg->scale, 
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
	int x, y;

	surface = cairo_image_surface_create_for_data( 
		VIPS_REGION_ADDR( or, r->left, r->top ), 
		CAIRO_FORMAT_ARGB32, 
		r->width, r->height, 
		VIPS_REGION_LSKIP( or ) );
	cr = cairo_create( surface );
	cairo_surface_destroy( surface );

	cairo_scale( cr, svg->scale, svg->scale );
	cairo_translate( cr, 
		-r->left / svg->scale, -r->top / svg->scale );

	/* rsvg is single-threaded, but we don't need to lock since we're
	 * running inside a non-threaded tilecache.
	 */
	if( !rsvg_handle_render_cairo( svg->page, cr ) ) {
		vips_error( class->nickname, 
			"%s", _( "SVG rendering failed" ) );
		return( -1 );
	}

	cairo_destroy( cr );

	/* Cairo makes BRGA, we must byteswap. We might not need to on SPARC,
	 * but I have no way of testing this :( 
	 */
	for( y = 0; y < r->height; y++ ) {
		VipsPel * restrict q;

		q = VIPS_REGION_ADDR( or, r->left, r->top + y );
		for( x = 0; x < r->width; x++ ) {
			VIPS_SWAP( VipsPel, q[0], q[2] );

			q += 4;
		}
	}

	return( 0 ); 
}

static int
vips_foreign_load_svg_load( VipsForeignLoad *load )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) load, 2 );

	/* Read to this image, then cache to out, see below.
	 */
	t[0] = vips_image_new(); 

	vips_foreign_load_svg_parse( svg, t[0] ); 
	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_svg_generate, NULL, svg, NULL ) )
		return( -1 );

	/* Don't use tilecache to keep the number of calls to
	 * svg_page_render() low. Don't thread the cache, we rely on
	 * locking to keep svg single-threaded.
	 */
	if( vips_linecache( t[0], &t[1],
		"tile_height", 128,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( t[1], load->real ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_svg_class_init( VipsForeignLoadSvgClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_svg_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "svgload";
	object_class->description = _( "load SVG with rsvg" );
	object_class->build = vips_foreign_load_svg_build;

	load_class->get_flags_filename = 
		vips_foreign_load_svg_get_flags_filename;
	load_class->get_flags = vips_foreign_load_svg_get_flags;
	load_class->load = vips_foreign_load_svg_load;

	VIPS_ARG_DOUBLE( class, "dpi", 11,
		_( "DPI" ),
		_( "Render at this DPI" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadSvg, dpi ),
		0.001, 100000.0, 72.0 );

	VIPS_ARG_DOUBLE( class, "scale", 12,
		_( "Scale" ),
		_( "Scale output by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadSvg, scale ),
		0.001, 100000.0, 1.0 );

}

static void
vips_foreign_load_svg_init( VipsForeignLoadSvg *svg )
{
	svg->dpi = 72.0;
	svg->scale = 1.0;
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

static int
vips_foreign_load_svg_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) load;
	VipsForeignLoadSvgFile *file = (VipsForeignLoadSvgFile *) load;

	GError *error = NULL;

	if( !(svg->page = rsvg_handle_new_from_file( 
		file->filename, &error )) ) { 
		vips_g_error( &error );
		return( -1 ); 
	}

	return( vips_foreign_load_svg_header( load ) );
}

static const char *vips_foreign_svg_suffs[] = {
	".svg",
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
	object_class->description = _( "load PDF with rsvg" );

	foreign_class->suffs = vips_foreign_svg_suffs;

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

static gboolean
vips_foreign_load_svg_is_a_buffer( const void *buf, size_t len )
{
	char *str = (char *) buf;

	int i;

	/* SVG documents are very freeform. They normally look like:
	 *
	 * <?xml version="1.0" encoding="UTF-8"?>
	 * <svg xmlns="http://www.w3.org/2000/svg" ...
	 *
	 * But there can be a doctype in there too. And case and whitespace can
	 * vary a lot. And the <?xml can be missing. 
	 *
	 * Simple rules:
	 * - first 24 chars are plain ascii
	 * - first 200 chars contain "<svg", upper or lower case.
	 *
	 * We could rsvg_handle_new_from_data() on the buffer, but that can be
	 * horribly slow for large documents. 
	 */
	if( len < 24 )
		return( 0 );
	for( i = 0; i < 24; i++ )
		if( !isascii( str[i] ) )
		return( 0 );

	for( i = 0; i < 200 && i < len - 5; i++ ) {
		char txt[5];

		/* 5, since we include the \0 at the end.
		 */
		vips_strncpy( txt, buf + i, 5 );
		if( strcasecmp( txt, "<svg" ) == 0 )
			return( 1 );
	}

	return( 0 );
}

static int
vips_foreign_load_svg_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadSvg *svg = (VipsForeignLoadSvg *) load;
	VipsForeignLoadSvgBuffer *buffer = 
		(VipsForeignLoadSvgBuffer *) load;

	GError *error = NULL;

	if( !(svg->page = rsvg_handle_new_from_data( 
		buffer->buf->data, buffer->buf->length, &error )) ) { 
		vips_g_error( &error );
		return( -1 ); 
	}

	return( vips_foreign_load_svg_header( load ) );
}

static void
vips_foreign_load_svg_buffer_class_init( 
	VipsForeignLoadSvgBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "svgload_buffer";
	object_class->description = _( "load SVG with rsvg" );

	load_class->is_a_buffer = vips_foreign_load_svg_is_a_buffer;
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

