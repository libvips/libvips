/* A byte source/sink .. it can be a pipe, socket, or perhaps a node.js stream.
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

/* Communicate with something like a socket or pipe. 
 */
typedef struct _VipsStream {
	VipsObject parent_object;

	/*< private >*/
	
	/* Read/write this fd if connected to a system pipe/socket. Override
	 * ::read() and ::write() to do something else.
	 */
	int descriptor;	

	/* If descriptor is a file, the filename we opened. Handy for error
	 * messages. 
	 */
	char *filename; 

	/* Set if this object is currently hooked up to something that's
	 * reading/writing bytes, like the libjpeg input system. 
	 *
	 * In this case, the format library will be in charge of the buffering
	 * and we can't read or write directly. 
	 */
	gboolean attached;

} VipsStream;

typedef struct _VipsStreamClass {
	VipsObjectClass parent_class;

} VipsStreamClass;

GType vips_stream_get_type( void );

void vips_stream_attach( VipsStream *stream );

#define VIPS_TYPE_STREAM_INPUT (vips_stream_input_get_type())
#define VIPS_STREAM_INPUT( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_STREAM_INPUT, VipsStreamInput ))
#define VIPS_STREAM_INPUT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_STREAM_INPUT, VipsStreamInputClass))
#define VIPS_IS_STREAM_INPUT( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_STREAM_INPUT ))
#define VIPS_IS_STREAM_INPUT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_STREAM_INPUT ))
#define VIPS_STREAM_INPUT_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_STREAM_INPUT, VipsStreamInputClass ))

/* Input or write to something like a socket or pipe. 
 */
typedef struct _VipsStreamInput {
	VipsStream parent_object;

	/*< public >*/

	/* These are NULL and 0 after _build(), they become valid after the
	 * first vips_stream_input_refill().
	 */
	unsigned char *next_byte;
	size_t bytes_available;

	/*< private >*/

	/* For reading from a file, we need to buffer some bytes. This is a
	 * small memory area we own and which we free on _finalize().
	 */
	int buffer_size;	
	unsigned char *buffer;	

	/* For a memory source, the blob we read from.
	 */
	VipsBlob *blob;

	/* Set on EOF.
	 */
	gboolean eof;

} VipsStreamInput;

typedef struct _VipsStreamInputClass {
	VipsStreamClass parent_class;

	/* If defined, read some bytes with this. Otherwise use read().
	 */
	ssize_t (*read)( VipsStreamInput *, unsigned char *, size_t );

} VipsStreamInputClass;

GType vips_stream_input_get_type( void );

VipsStreamInput *vips_stream_input_new_from_descriptor( int descriptor );
VipsStreamInput *vips_stream_input_new_from_filename( const char *filename );
VipsStreamInput *vips_stream_input_new_from_blob( VipsBlob *blob );
VipsStreamInput *vips_stream_input_new_from_buffer( void *buf, size_t len );
int vips_stream_input_refill( VipsStreamInput *stream );
void vips_stream_input_detach( VipsStreamInput *stream, 
	unsigned char *next_byte, size_t bytes_available );
gboolean vips_stream_input_eof( VipsStreamInput *stream );
unsigned char *vips_stream_input_sniff( VipsStreamInput *stream, int bytes );

#define VIPS_TYPE_STREAM_OUTPUT (vips_stream_output_get_type())
#define VIPS_STREAM_OUTPUT( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_STREAM_OUTPUT, VipsStreamOutput ))
#define VIPS_STREAM_OUTPUT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_STREAM_OUTPUT, VipsStreamOutputClass))
#define VIPS_IS_STREAM_OUTPUT( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_STREAM_OUTPUT ))
#define VIPS_IS_STREAM_OUTPUT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_STREAM_OUTPUT ))
#define VIPS_STREAM_OUTPUT_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_STREAM_OUTPUT, VipsStreamOutputClass ))

/* Read or output to something like a socket or pipe. 
 */
typedef struct _VipsStreamOutput {
	VipsStream parent_object;

	/*< private >*/
	
} VipsStreamOutput;

typedef struct _VipsStreamOutputClass {
	VipsStreamClass parent_class;

	/* If defined, output some bytes with this. Otherwise use write().
	 */
	ssize_t (*write)( VipsStreamOutput *, const unsigned char *, size_t );

} VipsStreamOutputClass;

GType vips_stream_output_get_type( void );

VipsStreamOutput *vips_stream_output_new_from_descriptor( int descriptor );
VipsStreamOutput *vips_stream_output_new_from_filename( const char *filename );
void vips_stream_output_detach( VipsStreamOutput *stream );
int vips_stream_output_write( VipsStreamOutput *stream,
	const unsigned char *buffer, size_t buffer_size );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_STREAM_H*/
