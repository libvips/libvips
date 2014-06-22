/* common defs for webp read/write
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

#ifndef VIPS_WEBP_H
#define VIPS_WEBP_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

extern const char *vips__webp_suffs[];

int vips__iswebp_buffer( const unsigned char *buf, size_t len );
int vips__iswebp( const char *filename );

int vips__webp_read_file_header( const char *name, VipsImage *out ); 
int vips__webp_read_file( const char *name, VipsImage *out ); 

int vips__webp_read_buffer_header( void *buf, size_t len, VipsImage *out ); 
int vips__webp_read_buffer( void *buf, size_t len, VipsImage *out ); 

int vips__webp_write_file( VipsImage *out, const char *filename, 
	int Q, gboolean lossless );
int vips__webp_write_buffer( VipsImage *out, void **buf, size_t *len, 
	int Q, gboolean lossless );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_WEBP_H*/
