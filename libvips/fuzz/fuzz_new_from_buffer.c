/* fuzz targets for libfuzzer
 * 
 * 28/7/17
 * 	- first attempt
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>

int 
vips__fuzztarget_new_from_buffer( const guint8 *data, size_t size ) 
{
	VipsImage *image;
	double d;

	/* Have one for each format as well.
	 */
	if( !(image = vips_image_new_from_buffer( data, size, "", NULL )) )
		/* libfuzzer does not allow error return.
		 */
		return( 0 );

	if( vips_avg( image, &d, NULL ) )
		return( 0 );

	g_object_unref( image ); 

	return( 0 );
}
