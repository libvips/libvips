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

	/* A descriptor we close with vips_tracked_close().
	 */
	int tracked_descriptor;	

	/* A descriptor we close close().
	 */
	int close_descriptor;	

	/* If descriptor is a file, the filename we opened. Handy for error
	 * messages. 
	 */
	char *filename; 

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

/* Read from something like a socket, file or memory area and present the data
 * with a simple seek / read interface.
 *
 * During the header phase, we save data from unseekable sources in a buffer
 * so readers can rewind and read again. We don't buffer data during the
 * decode stage.
 */
typedef struct _VipsStreamInput {
	VipsStream parent_object;

	/* We have two phases: 
	 *
	 * During the header phase, we save bytes read from the input (if this
	 * is an unseekable source) so that we can rewind and try again, if
	 * necessary.
	 *
	 * Once we reach decode phase, we no longer support rewind and the
	 * buffer of saved data is discarded.
	 */
	gboolean decode;

	/* TRUE is this input source supports rewind. If not, then we save data
	 * read during header phase in a buffer.
	 */
	gboolean rewindable;

	/*< private >*/

	/* The current read point.
	 */
	off_t read_position;

	/* Save data read during header phase here. If we rewind and try
	 * again, serve data from this until it runs out.
	 */
	GByteArray *header_bytes;

	/* Save the first few bytes here for file type sniffing.
	 */
	GByteArray *sniff;

	/* For a memory source, the blob we read from.
	 */
	VipsBlob *blob;

	/* Set on EOF.
	 */
	gboolean eof;

} VipsStreamInput;

typedef struct _VipsStreamInputClass {
	VipsStreamClass parent_class;

	/* Subclasses can define these to implement other input methods.
	 */
	ssize_t (*read)( VipsStreamInput *, unsigned char *, size_t );
	int (*rewind)( VipsStreamInput * );

} VipsStreamInputClass;

GType vips_stream_input_get_type( void );

VipsStreamInput *vips_stream_input_new_from_descriptor( int descriptor );
VipsStreamInput *vips_stream_input_new_from_filename( const char *filename );
VipsStreamInput *vips_stream_input_new_from_blob( VipsBlob *blob );
VipsStreamInput *vips_stream_input_new_from_memory( const void *data, 
	size_t size );

ssize_t vips_stream_input_read( VipsStreamInput *input, 
	unsigned char *buffer, size_t length );
int vips_stream_input_rewind( VipsStreamInput *input );
void vips_stream_input_decode( VipsStreamInput *input );
gboolean vips_stream_input_eof( VipsStreamInput *input );
unsigned char *vips_stream_input_sniff( VipsStreamInput *input, size_t length );

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

	/* For memory output, the blob we write to.
	 */
	VipsBlob *blob;

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
int vips_stream_output_write( VipsStreamOutput *stream,
	const unsigned char *buffer, size_t buffer_size );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_STREAM_H*/
