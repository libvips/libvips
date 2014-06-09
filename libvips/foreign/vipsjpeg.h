/* simple interface to our jpg functions
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

#ifndef VIPS_VIPSJPEG_H
#define VIPS_VIPSJPEG_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

extern const char *vips__jpeg_suffs[];

int vips__jpeg_write_file( VipsImage *in, 
	const char *filename, int Q, const char *profile, 
	gboolean optimize_coding, gboolean progressive, gboolean strip,
	gboolean no_subsample );
int vips__jpeg_write_buffer( VipsImage *in, 
	void **obuf, size_t *olen, int Q, const char *profile, 
	gboolean optimize_coding, gboolean progressive, gboolean strip,
	gboolean no_subsample );

int vips__isjpeg_buffer( void *buf, size_t len );
int vips__isjpeg( const char *filename );
int vips__jpeg_read_file( const char *name, VipsImage *out, 
	gboolean header_only, int shrink, gboolean fail, gboolean readbehind );
int vips__jpeg_read_buffer( void *buf, size_t len, VipsImage *out, 
	gboolean header_only, int shrink, int fail, gboolean readbehind );
int vips__jpeg_read_fd( int descriptor, VipsImage *out, 
	int shrink, int fail, gboolean readbehind );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_VIPSJPEG_H*/
