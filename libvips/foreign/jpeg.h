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

/* jpeglib includes jconfig.h, which can define HAVE_STDLIB_H ... which we
 * also define. Make sure it's turned off.
 */
#ifdef HAVE_STDLIB_H
#undef HAVE_STDLIB_H
#endif /*HAVE_STDLIB_H*/

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

#include <jpeglib.h>
#include <jerror.h>

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

int vips__set_exif_resolution( ExifData *ed, VipsImage *im );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_JPEG_H*/
