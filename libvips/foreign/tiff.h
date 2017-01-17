/* common defs for tiff read/write
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_TIFF_H
#define VIPS_TIFF_H

#include <tiffio.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

TIFF *vips__tiff_openout( const char *path, gboolean bigtiff );
TIFF *vips__tiff_openin( const char *path );

TIFF *vips__tiff_openin_buffer( VipsImage *image, 
	const void *data, size_t length );
TIFF *vips__tiff_openout_buffer( VipsImage *image, 
	gboolean bigtiff, void **out_data, size_t *out_length );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_TIFF_H*/
