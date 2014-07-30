/* load openslide from a file
 *
 * 5/12/11
 * 	- from openslideload.c
 * 28/2/12
 * 	- convert "layer" to "level" where externally visible
 * 11/4/12
 * 	- convert remaining uses of "layer" to "level"
 * 20/9/12
 * 	- add Leica filename suffix
 *	- drop glib log handler (unneeded with >= 3.3.0)
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

#ifdef HAVE_OPENSLIDE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "openslide2vips.h"

typedef struct _VipsForeignLoadOpenslide {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

	/* Load this level.
	 */
	int level;

	/* Don't crop to image bounds.
	 */
	gboolean whole_slide;

	/* Load this associated image. 
	 */
	char *associated;

} VipsForeignLoadOpenslide;

typedef VipsForeignLoadClass VipsForeignLoadOpenslideClass;

G_DEFINE_TYPE( VipsForeignLoadOpenslide, vips_foreign_load_openslide, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_openslide_get_flags_filename( const char *filename )
{
	/* We can't tell from just the filename, we need to know what part of
	 * the file the user wants. But it'll usually be partial.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_openslide_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadOpenslide *openslide = (VipsForeignLoadOpenslide *) load;
	VipsForeignFlags flags;

	flags = 0;
	if( !openslide->associated )
		flags |= VIPS_FOREIGN_PARTIAL;

	return( flags );
}

static int
vips_foreign_load_openslide_header( VipsForeignLoad *load )
{
	VipsForeignLoadOpenslide *openslide = (VipsForeignLoadOpenslide *) load;

	if( vips__openslide_read_header( openslide->filename, load->out, 
		openslide->level, openslide->whole_slide, 
		openslide->associated ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, openslide->filename );

	return( 0 );
}

static int
vips_foreign_load_openslide_load( VipsForeignLoad *load )
{
	VipsForeignLoadOpenslide *openslide = (VipsForeignLoadOpenslide *) load;

	if( !openslide->associated ) {
		if( vips__openslide_read( openslide->filename, load->real, 
			openslide->level, openslide->whole_slide ) )
			return( -1 );
	}
	else {
		if( vips__openslide_read_associated( 
			openslide->filename, load->real, 
			openslide->associated ) )
			return( -1 );
	}

	return( 0 );
}

static const char *vips_foreign_openslide_suffs[] = {
	".svs", 	/* Aperio */
	".vms", ".vmu", ".ndpi",  /* Hamamatsu */
	".scn",		/* Leica */
	".mrxs", 	/* MIRAX */
	".svslide",	/* Sakura */
	".tif", 	/* Trestle */
	".bif", 	/* Ventana */
	NULL
};

static void
vips_foreign_load_openslide_class_init( VipsForeignLoadOpenslideClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "openslideload";
	object_class->description = _( "load file with OpenSlide" );

	/* We need to be ahead of the tiff sniffer since many OpenSlide
	 * formats are tiff derivatives. If we see a tiff which would be
	 * better handled by the vips tiff loader we are careful to say no.
	 */
	foreign_class->priority = 100;
	foreign_class->suffs = vips_foreign_openslide_suffs;

	load_class->is_a = vips__openslide_isslide;
	load_class->get_flags_filename = 
		vips_foreign_load_openslide_get_flags_filename;
	load_class->get_flags = vips_foreign_load_openslide_get_flags;
	load_class->header = vips_foreign_load_openslide_header;
	load_class->load = vips_foreign_load_openslide_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadOpenslide, filename ),
		NULL );

	VIPS_ARG_INT( class, "level", 10,
		_( "Level" ),
		_( "Load this level from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadOpenslide, level ),
		0, 100000, 0 );

	VIPS_ARG_BOOL( class, "whole_slide", 11,
		_( "Whole slide" ),
		_( "Output entire side area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadOpenslide, whole_slide ),
		FALSE ); 

	VIPS_ARG_STRING( class, "associated", 12, 
		_( "Associated" ),
		_( "Load this associated image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadOpenslide, associated ),
		NULL );
}

static void
vips_foreign_load_openslide_init( VipsForeignLoadOpenslide *openslide )
{
}

#endif /*HAVE_OPENSLIDE*/
