/* Read a file using libMagick
 * 
 * 17/12/11
 * 	- just a stub
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

/* Turn on debugging output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>

int
im_magick2vips( const char *filename, IMAGE *out )
{
	VipsImage *t;

	if( vips_magickload( filename, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
ismagick( const char *filename )
{
	return( vips_foreign_is_a( "magickload", filename ) );
}

static const char *magick_suffs[] = { NULL };

/* magick format adds no new members.
 */
typedef VipsFormat VipsFormatMagick;
typedef VipsFormatClass VipsFormatMagickClass;

static void
vips_format_magick_class_init( VipsFormatMagickClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "magick";
	object_class->description = _( "libMagick-supported" );

	format_class->is_a = ismagick;
	format_class->load = im_magick2vips;
	format_class->suffs = magick_suffs;

	/* This can be very slow :-( Use our own jpeg/tiff/png etc. loaders in
	 * preference if we can.
	 */
	format_class->priority = -1000;
}

static void
vips_format_magick_init( VipsFormatMagick *object )
{
}

G_DEFINE_TYPE( VipsFormatMagick, vips_format_magick, VIPS_TYPE_FORMAT );

