/* Read matlab save files with libmatio
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
im_mat2vips( const char *filename, IMAGE *out )
{
	VipsImage *t;

	if( vips_matload( filename, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
ismat( const char *filename )
{
	return( vips_foreign_is_a( "matload", filename ) );
}

static const char *mat_suffs[] = { ".mat", NULL };

typedef VipsFormat VipsFormatMat;
typedef VipsFormatClass VipsFormatMatClass;

static void
vips_format_mat_class_init( VipsFormatMatClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "mat";
	object_class->description = _( "Matlab" );

	format_class->is_a = ismat;
	format_class->load = im_mat2vips;
	format_class->save = NULL;
	format_class->suffs = mat_suffs;
}

static void
vips_format_mat_init( VipsFormatMat *object )
{
}

G_DEFINE_TYPE( VipsFormatMat, vips_format_mat, VIPS_TYPE_FORMAT );

