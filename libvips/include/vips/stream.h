/* A byte source .. it can be a pipe, socket, or perhaps a node.js stream.
 *
 * J.Cupitt, 19/6/14
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

#ifndef VIPS_STREAM_H
#define VIPS_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_STREAM (vips_stream_get_type())
#define VIPS_STREAM( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_STREAM, VipsStream ))
#define VIPS_STREAM_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_STREAM, VipsStreamClass))
#define VIPS_IS_STREAM( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_STREAM ))
#define VIPS_IS_STREAM_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_STREAM ))
#define VIPS_STREAM_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_STREAM, VipsStreamClass ))

/* Sub-area of image.
 */
typedef struct _VipsStream {
	VipsObject parent_object;

	/*< public >*/

	unsigned char *next_byte;
	size_t bytes_available;

	/*< private >*/
	
	size_t buffer_size;	/* How many bytes we buffer ... eg. 4096 */
	int descriptor;		/* The fd we read from */

	unsigned char *buffer;	/* The start of our buffer */

	/* Set if this stream is currently hooked up to something that's
	 * reading bytes.
	 */
	gboolean attached;

} VipsStream;

typedef struct _VipsStreamClass {
	VipsObjectClass parent_class;

	/* If defined, refill the buffer with this.
	 */
	int (*read)( VipsStream * );

} VipsStreamClass;

GType vips_stream_get_type( void );

VipsStream *vips_stream_new_from_descriptor( int descriptor );
int vips_stream_read( VipsStream *stream );
void vips_stream_attach( VipsStream *stream );
void vips_stream_detach( VipsStream *stream, 
	unsigned char *next_byte, size_t bytes_available );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_STREAM_H*/
