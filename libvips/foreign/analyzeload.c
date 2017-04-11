/* load analyze from a file
 *
 * 5/12/11
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#ifdef HAVE_ANALYZE

#include "pforeign.h"

typedef struct _VipsForeignLoadAnalyze {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadAnalyze;

typedef VipsForeignLoadClass VipsForeignLoadAnalyzeClass;

G_DEFINE_TYPE( VipsForeignLoadAnalyze, vips_foreign_load_analyze, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_analyze_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_analyze_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static int
vips_foreign_load_analyze_header( VipsForeignLoad *load )
{
	VipsForeignLoadAnalyze *analyze = (VipsForeignLoadAnalyze *) load;

	if( vips__analyze_read_header( analyze->filename, load->out ) ) 
		return( -1 );

	VIPS_SETSTR( load->out->filename, analyze->filename );

	return( 0 );
}

static int
vips_foreign_load_analyze_load( VipsForeignLoad *load )
{
	VipsForeignLoadAnalyze *analyze = (VipsForeignLoadAnalyze *) load;

	if( vips__analyze_read( analyze->filename, load->real ) ) 
		return( -1 );

	return( 0 );
}

static const char *vips_foreign_analyze_suffs[] = { ".img", ".hdr", NULL };

static void
vips_foreign_load_analyze_class_init( VipsForeignLoadAnalyzeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "analyzeload";
	object_class->description = _( "load an Analyze6 image" );

	foreign_class->suffs = vips_foreign_analyze_suffs;

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -50;

	load_class->is_a = vips__isanalyze;
	load_class->get_flags_filename = 
		vips_foreign_load_analyze_get_flags_filename;
	load_class->get_flags = vips_foreign_load_analyze_get_flags;
	load_class->header = vips_foreign_load_analyze_header;
	load_class->load = vips_foreign_load_analyze_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadAnalyze, filename ),
		NULL );
}

static void
vips_foreign_load_analyze_init( VipsForeignLoadAnalyze *analyze )
{
}

#endif /*HAVE_ANALYZE*/

/**
 * vips_analyzeload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Load an Analyze 6.0 file. If @filename is "fred.img", this will look for
 * an image header called "fred.hdr" and pixel data in "fred.img". You can
 * also load "fred" or "fred.hdr".
 *
 * Images are
 * loaded lazilly and byte-swapped, if necessary. The Analyze metadata is read
 * and attached.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_analyzeload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "analyzeload", ap, filename, out );
	va_end( ap );

	return( result );
}
