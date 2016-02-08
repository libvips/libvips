/* load PDF with libpoppler
 *
 * 7/2/16
 * 	- from openslideload.c
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

#ifdef HAVE_POPPLER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include <cairo.h>
#include <poppler.h>

typedef struct _VipsForeignLoadPoppler {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

	/* Load this page.
	 */
	int page_no;

	/* Render at this DPI.
	 */
	double dpi;

	/* Calculate this from DPI. At 72 DPI, we render 1:1 with cairo.
	 */
	double scale;

	char *uri;
	PopplerDocument *doc;
	PopplerPage *page;

} VipsForeignLoadPoppler;

typedef VipsForeignLoadClass VipsForeignLoadPopplerClass;

G_DEFINE_TYPE( VipsForeignLoadPoppler, vips_foreign_load_poppler, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_poppler_dispose( GObject *gobject )
{
	VipsForeignLoadPoppler *poppler = (VipsForeignLoadPoppler *) gobject;

	VIPS_FREE( poppler->uri );
	VIPS_UNREF( poppler->page );
	VIPS_UNREF( poppler->doc );

	G_OBJECT_CLASS( vips_foreign_load_poppler_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_poppler_build( VipsObject *object )
{
	VipsForeignLoadPoppler *poppler = (VipsForeignLoadPoppler *) object;

	if( !vips_object_argument_isset( object, "scale" ) )
		poppler->scale = poppler->dpi / 72.0;

	if( VIPS_OBJECT_CLASS( vips_foreign_load_poppler_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_poppler_get_flags_filename( const char *filename )
{
	/* We can render any part of the page on demand.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_poppler_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

/* String-based metadatra fields we extract.
 */
typedef struct _VipsForeignLoadPopperMetadata {
	char *(*poppler_fetch)( PopplerDocument *doc );
	char *field;
} VipsForeignLoadPopperMetadata;

static VipsForeignLoadPopperMetadata vips_foreign_load_poppler_metadata[] = {
	{ poppler_document_get_title, "poppler-title" },
	{ poppler_document_get_author, "poppler-author" },
	{ poppler_document_get_subject, "poppler-subject" },
	{ poppler_document_get_keywords, "poppler-keywords" },
	{ poppler_document_get_creator, "poppler-creator" },
	{ poppler_document_get_producer, "poppler-producer" },
	{ poppler_document_get_metadata, "poppler-metadata" },
};
static int n_metadata = VIPS_NUMBER( vips_foreign_load_poppler_metadata );

static void
vips_foreign_load_poppler_parse( VipsForeignLoadPoppler *poppler, 
	VipsImage *out )
{
	PopplerRectangle crop_box;
	double width;
	double height;
	double res;
	int i;

	poppler_page_get_size( poppler->page, &width, &height ); 

	poppler_page_get_crop_box( poppler->page, &crop_box ); 

	/* We need pixels/mm for vips.
	 */
	res = poppler->dpi / 25.4;

	vips_image_init_fields( out, 
		width * poppler->scale, height * poppler->scale, 
		4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, res, res );

	VIPS_SETSTR( out->filename, poppler->filename );

	/* We render to a linecache, so fat strips work well.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_FATSTRIP, NULL );

	/* Extract and attach metadata.
	 */
	vips_image_set_int( out, "poppler-n_pages", 
		poppler_document_get_n_pages( poppler->doc ) );

	for( i = 0; i < n_metadata; i++ ) {
		VipsForeignLoadPopperMetadata *metadata = 
			&vips_foreign_load_poppler_metadata[i];

		char *str;

		if( (str = metadata->poppler_fetch( poppler->doc )) ) { 
			vips_image_set_string( out, metadata->field, str ); 
			g_free( str );
		}
	}
}

static int
vips_foreign_load_poppler_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadPoppler *poppler = (VipsForeignLoadPoppler *) load;

	char *path;
	GError *error = NULL;

	/* We need an absolute path for a URI.
	 */
	path = vips_realpath( poppler->filename );
	if( !(poppler->uri = g_filename_to_uri( path, NULL, &error )) ) { 
		free( path );
		vips_g_error( &error );
		return( -1 ); 
	}
	free( path );

	if( !(poppler->doc = poppler_document_new_from_file( 
		poppler->uri, NULL, &error )) ) { 
		vips_g_error( &error );
		return( -1 ); 
	}

	if( !(poppler->page = poppler_document_get_page( poppler->doc, 
		poppler->page_no )) ) {
		vips_error( class->nickname, 
			_( "unable to load page %d" ), poppler->page_no );
		return( -1 ); 
	}

	vips_foreign_load_poppler_parse( poppler, load->out ); 

	return( 0 );
}

static int
vips_foreign_load_poppler_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadPoppler *poppler = (VipsForeignLoadPoppler *) a;
	VipsRect *r = &or->valid;

	cairo_surface_t *surface;
	cairo_t *cr;
	int x, y;

	/* Poppler won't always paint the background.
	 */
	vips_region_black( or ); 

	surface = cairo_image_surface_create_for_data( 
		VIPS_REGION_ADDR( or, r->left, r->top ), 
		CAIRO_FORMAT_ARGB32, 
		r->width, r->height, 
		VIPS_REGION_LSKIP( or ) );
	cr = cairo_create( surface );
	cairo_surface_destroy( surface );

	cairo_scale( cr, poppler->scale, poppler->scale );
	cairo_translate( cr, 
		-r->left / poppler->scale, -r->top / poppler->scale );

	/* Poppler is single-threaded, but we don't need to lock since we're
	 * running inside a non-threaded tilecache.
	 */
	poppler_page_render( poppler->page, cr );

	cairo_destroy( cr );

	/* Cairo makes BRGA, we must byteswap. We might not need to on SPARC,
	 * but I have no way of testing this :( 
	 */
	for( y = 0; y < r->height; y++ ) {
		VipsPel *q;

		q = VIPS_REGION_ADDR( or, r->left, r->top + y );
		for( x = 0; x < r->width; x++ ) {
			VIPS_SWAP( VipsPel, q[0], q[2] );

			q += 4;
		}
	}

	return( 0 ); 
}

static int
vips_foreign_load_poppler_load( VipsForeignLoad *load )
{
	VipsForeignLoadPoppler *poppler = (VipsForeignLoadPoppler *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) load, 2 );

	/* Read to this image, then cache to out, see below.
	 */
	t[0] = vips_image_new(); 

	vips_foreign_load_poppler_parse( poppler, t[0] ); 
	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_poppler_generate, NULL, poppler, NULL ) )
		return( -1 );

	/* Don't use tilecache to keep the number of calls to
	 * poppler_page_render() low. Don't thread the cache, we rely on
	 * locking to keep poppler single-threaded.
	 */
	if( vips_linecache( t[0], &t[1],
		"tile_height", 128,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( t[1], load->real ) ) 
		return( -1 );

	return( 0 );
}

static const char *vips_foreign_poppler_suffs[] = {
	".pdf",
	NULL
};

static void
vips_foreign_load_poppler_class_init( VipsForeignLoadPopplerClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_poppler_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "popplerload";
	object_class->description = _( "load PDF with poppler" );
	object_class->build = vips_foreign_load_poppler_build;

	foreign_class->suffs = vips_foreign_poppler_suffs;

	load_class->get_flags_filename = 
		vips_foreign_load_poppler_get_flags_filename;
	load_class->get_flags = vips_foreign_load_poppler_get_flags;
	load_class->header = vips_foreign_load_poppler_header;
	load_class->load = vips_foreign_load_poppler_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPoppler, filename ),
		NULL );

	VIPS_ARG_INT( class, "page", 10,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPoppler, page_no ),
		0, 100000, 0 );

	VIPS_ARG_DOUBLE( class, "dpi", 11,
		_( "DPI" ),
		_( "Render at this DPI" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPoppler, dpi ),
		0.001, 100000.0, 72.0 );

	VIPS_ARG_DOUBLE( class, "scale", 12,
		_( "Scale" ),
		_( "Scale output by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPoppler, scale ),
		0.001, 100000.0, 1.0 );

}

static void
vips_foreign_load_poppler_init( VipsForeignLoadPoppler *poppler )
{
	poppler->dpi = 72.0;
	poppler->scale = 1.0;
}

#endif /*HAVE_POPPLER*/
