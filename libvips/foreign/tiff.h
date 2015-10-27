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

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

extern const char *vips__foreign_tiff_suffs[];

void vips__tiff_init( void );

int vips__tiff_write( VipsImage *in, const char *filename, 
	VipsForeignTiffCompression compression, int Q, 
		VipsForeignTiffPredictor predictor,
	char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	gboolean squash,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg );

int vips__tiff_read_header( const char *filename, VipsImage *out, int page );
int vips__tiff_read( const char *filename, VipsImage *out, 
	int page, gboolean readbehind );
gboolean vips__istifftiled( const char *filename );
gboolean vips__istiff_buffer( const void *buf, size_t len );
gboolean vips__istiff( const char *filename );

int vips__tiff_read_header_buffer( const void *buf, size_t len, VipsImage *out, 
	int page );
int vips__tiff_read_buffer( const void *buf, size_t len, VipsImage *out, 
	int page, gboolean readbehind );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_TIFF_H*/
