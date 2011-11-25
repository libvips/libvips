/* load vips from a file
 *
 * 24/11/11
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>

typedef VipsFileLoad VipsFileLoadVips;
typedef VipsFileLoadClass VipsFileLoadVipsClass;

G_DEFINE_TYPE( VipsFileLoadVips, vips_file_load_vips, VIPS_TYPE_FILE_SAVE );

static int
vips_file_load_vips_build( VipsObject *object )
{
	if( VIPS_OBJECT_CLASS( vips_file_load_vips_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static int
vips_file_load_vips_is_a( const char *filename )
{
	unsigned char buf[4];

	if( vips__get_bytes( filename, buf, 4 ) ) {
		if( buf[0] == 0x08 && buf[1] == 0xf2 &&
			buf[2] == 0xa6 && buf[3] == 0xb6 )
			/* SPARC-order VIPS image.
			 */
			return( 1 );
		else if( buf[3] == 0x08 && buf[2] == 0xf2 &&
			buf[1] == 0xa6 && buf[0] == 0xb6 )
			/* INTEL-order VIPS image.
			 */
			return( 1 );
	}

	return( 0 );
}

static int
vips_file_load_vips_header( VipsFileLoad *load )
{
}

static int
vips_file_load_vips_load( VipsFileLoad *load )
{
}

static const char *vips_suffs[] = { ".v", NULL };

static void
vips_file_load_jpeg_class_init( VipsFileLoadJpegClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFileClass *file_class = (VipsLoadClass *) class;
	VipsFileLoadClass *load_class = (VipsFileLoadClass *) class;

	object_class->nickname = "vipsload";
	object_class->description = _( "load vips from file" );
	object_class->build = vips_file_load_vips_build;

	file_class->suffs = vips_suffs;

	load_class->is_a = vips_file_load_vips_is_a;
	load_class->header = vips_file_load_vips_header;
	load_class->load = vips_file_load_vips_load;

}

static void
vips_file_load_vips_init( VipsFileLoadVips *vips )
{
}

