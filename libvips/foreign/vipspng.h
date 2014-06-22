/* common defs for png read/write
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

#ifndef VIPS_PNG_H
#define VIPS_PNG_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int vips__png_header( const char *name, VipsImage *out );
int vips__png_read( const char *name, VipsImage *out, gboolean readbehind );
int vips__png_ispng_buffer( const unsigned char *buf, size_t len );
int vips__png_ispng( const char *filename );
gboolean vips__png_isinterlaced( const char *filename );
extern const char *vips__png_suffs[];
int vips__png_read_buffer( char *buffer, size_t length, VipsImage *out, 
	gboolean readbehind  );
int vips__png_header_buffer( char *buffer, size_t length, VipsImage *out );
int vips__png_read_stream( VipsStreamInput *stream, VipsImage *out, 
	gboolean readbehind );

int vips__png_write( VipsImage *in, const char *filename, 
	int compress, int interlace );
int vips__png_write_buf( VipsImage *in, 
	void **obuf, size_t *olen, int compression, int interlace );
int vips__png_write_stream( VipsImage *in, 
	VipsStreamOutput *stream, int compression, int interlace );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PNG_H*/
