/* A dynamic memory buffer that expands as you write.
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

#ifndef VIPS_DBUF_H
#define VIPS_DBUF_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vips.h>

/* A buffer in the process of being written to ... multiple calls to 
 * vips_dbuf_append add to it. 
 */

typedef struct _VipsDbuf {
	/* All fields are private.
	 */
	/*< private >*/

	/* The current base, and the size of the allocated memory area.
	 */
	char *data;
	size_t max_size;

	/* And the write point.
	 */
	size_t write_point;
} VipsDbuf; 

void vips_dbuf_destroy( VipsDbuf *buf );
void vips_dbuf_init( VipsDbuf *buf );
gboolean vips_dbuf_append( VipsDbuf *dbuf, const char *data, size_t size );
gboolean vips_dbuf_appendf( VipsDbuf *dbuf, const char *fmt, ... );
void vips_dbuf_rewind( VipsDbuf *dbuf );
void vips_dbuf_destroy( VipsDbuf *dbuf );
char *vips_dbuf_string( VipsDbuf *dbuf, size_t *size );
char *vips_dbuf_steal( VipsDbuf *dbuf, size_t *size );

#endif /*VIPS_DBUF_H*/

#ifdef __cplusplus
}
#endif /*__cplusplus*/
