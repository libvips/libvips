/* Read a ppm file.
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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
im_ppm2vips( const char *filename, IMAGE *out )
{
	VipsImage *t;

	if( vips_ppmload( filename, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
isppm( const char *filename )
{
	return( vips_foreign_is_a( "ppmload", filename ) );
}

static VipsFormatFlags
ppm_flags( const char *filename )
{
	return( vips_foreign_flags( "ppmload", filename ) );
}

static const char *ppm_suffs[] = { ".ppm", ".pgm", ".pbm", ".pfm", NULL };

/* ppm format adds no new members.
 */
typedef VipsFormat VipsFormatPpm;
typedef VipsFormatClass VipsFormatPpmClass;

static void
vips_format_ppm_class_init( VipsFormatPpmClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "ppm";
	object_class->description = _( "PPM/PBM/PNM/PFM" );

	format_class->is_a = isppm;
	format_class->load = im_ppm2vips;
	format_class->save = im_vips2ppm;
	format_class->get_flags = ppm_flags;
	format_class->suffs = ppm_suffs;
}

static void
vips_format_ppm_init( VipsFormatPpm *object )
{
}

G_DEFINE_TYPE( VipsFormatPpm, vips_format_ppm, VIPS_TYPE_FORMAT );

