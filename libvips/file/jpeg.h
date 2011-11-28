/* common defs for jpeg read/write
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_JPEG_H
#define VIPS_JPEG_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Define a new error handler for when we bomb out.
 */
typedef struct {
	/* Public fields.
	 */
	struct jpeg_error_mgr pub;

	/* Private stuff for us.
	 */
	jmp_buf jmp;		/* longjmp() here to get back to VIPS */
	FILE *fp;		/* fclose() if non-NULL */
} ErrorManager;

void vips__new_output_message( j_common_ptr cinfo );
void vips__new_error_exit( j_common_ptr cinfo );

int vips__jpeg_write_file( VipsImage *in, 
	const char *filename, int Q, const char *profile );
int vips__jpeg_write_buffer( VipsImage *in, 
	void **obuf, int *olen, int Q, const char *profile );

int vips__isjpeg( const char *filename );
int vips__jpeg_read_file( const char *name, VipsImage *out, 
	gboolean header_only,
	int shrink, gboolean fail );
int vips__jpeg_read_buffer( void *buf, size_t len, VipsImage *out, 
	gboolean header_only,
	int shrink, int fail );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_JPEG_H*/
