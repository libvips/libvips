/* Read Radiance (.hdr) files 
 *
 * 20/12/11
 * 	- just a compat stub
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>

int
im_rad2vips( const char *filename, IMAGE *out )
{
	VipsImage *t;

	if( vips_radload( filename, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
israd( const char *filename )
{
	return( vips_foreign_is_a( "radload", filename ) );
}

int
im_vips2rad( IMAGE *in, const char *filename )
{
	return( vips_radsave( in, filename, NULL ) ); 
}

static const char *rad_suffs[] = { ".hdr", NULL };

typedef VipsFormat VipsFormatRad;
typedef VipsFormatClass VipsFormatRadClass;

static void
vips_format_rad_class_init( VipsFormatRadClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "rad";
	object_class->description = _( "Radiance" );

	format_class->is_a = israd;
	format_class->load = im_rad2vips;
	format_class->save = im_vips2rad;
	format_class->suffs = rad_suffs;
}

static void
vips_format_rad_init( VipsFormatRad *object )
{
}

G_DEFINE_TYPE( VipsFormatRad, vips_format_rad, VIPS_TYPE_FORMAT );

