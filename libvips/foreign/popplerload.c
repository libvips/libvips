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
	int dpi;

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

static int
vips_foreign_load_poppler_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadPoppler *poppler = (VipsForeignLoadPoppler *) load;

	GError *error = NULL;
	double width;
	double height;

	poppler->uri = g_strdup_printf( "file://%s", poppler->filename ); 

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

	poppler_page_get_size( poppler->page, &width, &height ); 

	vips_image_init_fields( load->out, width, height, 3, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );

	VIPS_SETSTR( load->out->filename, poppler->filename );

	return( 0 );
}

static int
vips_foreign_load_poppler_load( VipsForeignLoad *load )
{
	VipsForeignLoadPoppler *poppler = (VipsForeignLoadPoppler *) load;

	cairo_t *cr;

	poppler_page_render( poppler->page, cr );

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

	VIPS_ARG_INT( class, "dpi", 10,
		_( "DPI" ),
		_( "Render at this DPI" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPoppler, dpi ),
		1, 100000, 72 );

}

static void
vips_foreign_load_poppler_init( VipsForeignLoadPoppler *poppler )
{
}

#endif /*HAVE_POPPLER*/
