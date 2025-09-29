/* common defs for jpeg read/write
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

#ifndef VIPS_JPEG_H
#define VIPS_JPEG_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* jpeglib defines its own boolean type as an enum which then clashes with
 * everyone elses. Rename it as jboolean.
 */
#define boolean jboolean

/* Any TRUE/FALSE macros which have crept in will cause terrible confusion as
 * well.
 */
#ifdef TRUE
#undef TRUE
#endif /*TRUE*/

#ifdef FALSE
#undef FALSE
#endif /*FALSE*/

#include <setjmp.h>
#include <jpeglib.h>
#include <jerror.h>

/* Our custom error message codes.
 */
#define JERR_VIPS_IMAGE_EOF (1000)
#define JWRN_VIPS_IMAGE_EOF JERR_VIPS_IMAGE_EOF
#define JERR_VIPS_TARGET_WRITE (1001)

/* Define a new error handler for when we bomb out.
 */
typedef struct {
	/* Public fields.
	 */
	struct jpeg_error_mgr pub;

	/* Private stuff for us.
	 */
	jmp_buf jmp; /* longjmp() here to get back to VIPS */
	FILE *fp;	 /* fclose() if non-NULL */
} ErrorManager;

/* Stuff we track during a read.
 */
typedef struct _ReadJpeg {
	VipsImage *out;

	/* Shrink by this much during load. 1, 2, 4, 8.
	 */
	int shrink;

	/* Types of error to cause failure.
	 */
	VipsFailOn fail_on;

	struct jpeg_decompress_struct cinfo;
	ErrorManager eman;
	gboolean invert_pels;

	/* Use orientation tag to automatically rotate and flip image
	 * during load.
	 */
	gboolean autorotate;

	/* Remove DoS limits.
	 */
	gboolean unlimited;

	/* cinfo->output_width and height can be larger than we want since
	 * libjpeg rounds up on shrink-on-load. This is the real size we will
	 * output, as opposed to the size we decompress to.
	 */
	int output_width;
	int output_height;

	/* The source we read from.
	 */
	VipsSource *source;

} ReadJpeg;

extern const char *vips__jpeg_message_table[];

void vips__new_output_message(j_common_ptr cinfo);
void vips__new_error_exit(j_common_ptr cinfo);

ReadJpeg *vips__readjpeg_new(VipsSource *source, VipsImage *out,
	int shrink, VipsFailOn fail_on, gboolean autorotate,
	gboolean unlimited);
int vips__readjpeg_open_input(ReadJpeg *jpeg);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_JPEG_H*/
