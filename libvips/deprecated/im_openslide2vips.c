/* read with openslide
 *
 * 17/12/11
 * 	- just a stub
 * 11/4/12
 * 	- support :level,associated in filenames
 * 20/9/12
 *	- add Leica filename suffix
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
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>

static int
im_openslide2vips( const char *name, IMAGE *out )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q;
	char *associated;
	int level;
	char *endptr;
	VipsImage *t;

	im_filename_split( name, filename, mode );
	level = 0;
	associated = NULL;
	p = &mode[0];
	if( (q = im_getnextoption( &p )) ) {
		level = strtoul( q, &endptr, 10 );
		if( *endptr ) {
			vips_error( "openslide2vips", "%s",
				_( "level must be a number" ) );
			return( -1 );
		}
	}
	if( (q = im_getnextoption( &p )) ) 
		associated = q;

	if( vips_openslideload( filename, &t, 
		"level", level,
		"associated", associated,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static const char *openslide_suffs[] = { 
	".svs", 	/* Aperio */
	".vms", ".vmu", ".ndpi",  /* Hamamatsu */
	".scn",		/* Leica */
	".mrxs", 	/* MIRAX */
	".svslide",	/* Sakura */
	".tif", 	/* Trestle */
	".bif", 	/* Ventana */
	NULL
};

static VipsFormatFlags
openslide_flags( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( (VipsFormatFlags) 
		vips_foreign_flags( "openslideload", filename ) );
}

static int
isopenslide( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( vips_foreign_is_a( "openslideload", filename ) );
}

/* openslide format adds no new members.
 */
typedef VipsFormat VipsFormatOpenslide;
typedef VipsFormatClass VipsFormatOpenslideClass;

static void
vips_format_openslide_class_init( VipsFormatOpenslideClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "im_openslide";
	object_class->description = _( "Openslide" );

	format_class->priority = 100;
	format_class->is_a = isopenslide;
	format_class->load = im_openslide2vips;
	format_class->get_flags = openslide_flags;
	format_class->suffs = openslide_suffs;
}

static void
vips_format_openslide_init( VipsFormatOpenslide *object )
{
}

G_DEFINE_TYPE( VipsFormatOpenslide, vips_format_openslide, VIPS_TYPE_FORMAT );

