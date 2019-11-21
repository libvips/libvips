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

	/* A descriptor we close with close().
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

const char *vips_stream_filename( VipsStream *stream );
const char *vips_stream_nick( VipsStream *stream );

#define VIPS_TYPE_STREAMI (vips_streami_get_type())
#define VIPS_STREAMI( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_STREAMI, VipsStreami ))
#define VIPS_STREAMI_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_STREAMI, VipsStreamiClass))
#define VIPS_IS_STREAMI( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_STREAMI ))
#define VIPS_IS_STREAMI_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_STREAMI ))
#define VIPS_STREAMI_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_STREAMI, VipsStreamiClass ))

/* Read from something like a socket, file or memory area and present the data
 * with a unified seek / read / map interface.
 *
 * During the header phase, we save data from unseekable streams in a buffer
 * so readers can rewind and read again. We don't buffer data during the
 * decode stage.
 */
typedef struct _VipsStreami {
	VipsStream parent_object;

	/* We have two phases: 
	 *
	 * During the header phase, we save bytes read from the input (if this
	 * is an unseekable stream) so that we can rewind and try again, if
	 * necessary.
	 *
	 * Once we reach decode phase, we no longer support rewind and the
	 * buffer of saved data is discarded.
	 */
	gboolean decode;

	/* TRUE if this input is something like a pipe. These don't support
	 * stream or map -- all you can do is read() bytes sequentially.
	 *
	 * If you attempt to map or get the size of a pipe-style input, it'll 
	 * get read entirely into memory. Seeks will cause read up to the seek
	 * point.
	 */
	gboolean is_pipe;

	/* The current read point and length.
	 *
	 * length is -1 for is_pipe sources.
	 *
	 * off_t can be 32 bits on some platforms, so make sure we have a 
	 * full 64.
	 */
	gint64 read_position;
	gint64 length;

	/*< private >*/

	/* For sources where we have the whole image in memory (from a memory
	 * buffer, from mmaping the file, from reading the pipe into memory), 
	 * a pointer to the start.
	 */
	const void *data;

	/* For is_pipe sources, save data read during header phase here. If 
	 * we rewind and try again, serve data from this until it runs out.
	 *
	 * If we need to force the whole pipe into memory, read everything to
	 * this and put a copy pf the pointer in data.
	 */
	GByteArray *header_bytes;

	/* Save the first few bytes here for file type sniffing.
	 */
	GByteArray *sniff;

	/* For a memory stream, the blob we read from. 
	 */
	VipsBlob *blob;

	/* If we mmaped the file, whet we need to unmmap on finalize.
	 */
	void *mmap_baseaddr;
	size_t mmap_length;

} VipsStreami;

typedef struct _VipsStreamiClass {
	VipsStreamClass parent_class;

	/* Subclasses can define these to implement other streami methods.
	 */

	/* Read from the stream into the supplied buffer, args exactly as
	 * read(2). Set errno on error.
	 */
	ssize_t (*read)( VipsStreami *, void *, size_t );

	/* Seek to a certain position, args exactly as lseek(2). Set errno on
	 * error.
	 *
	 * Unseekable streams should always return -1. VipsStreami will then
	 * seek by _read()ing bytes into memory as required.
	 *
	 * We have to use int64 rather than off_t, since we must work on
	 * Windows, where off_t can be 32-bits.
	 */
	gint64 (*seek)( VipsStreami *, gint64, int );

} VipsStreamiClass;

GType vips_streami_get_type( void );

VipsStreami *vips_streami_new_from_descriptor( int descriptor );
VipsStreami *vips_streami_new_from_filename( const char *filename );
VipsStreami *vips_streami_new_from_blob( VipsBlob *blob );
VipsStreami *vips_streami_new_from_memory( const void *data, size_t size );
VipsStreami *vips_streami_new_from_options( const char *options );

void vips_streami_minimise( VipsStreami *streami );
int vips_streami_unminimise( VipsStreami *streami );
int vips_streami_decode( VipsStreami *streami );
ssize_t vips_streami_read( VipsStreami *streami, void *data, size_t length );
const void *vips_streami_map( VipsStreami *streami, size_t *length );
gboolean vips_streami_is_mappable( VipsStreami *streami );
gint64 vips_streami_seek( VipsStreami *streami, gint64 offset, int whence );
int vips_streami_rewind( VipsStreami *streami );
size_t vips_streami_sniff_at_most( VipsStreami *streami, 
	unsigned char **data, size_t length );
unsigned char *vips_streami_sniff( VipsStreami *streami, size_t length );
gint64 vips_streami_size( VipsStreami *streami ); 

#define VIPS_TYPE_STREAMIU (vips_streamiu_get_type())
#define VIPS_STREAMIU( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_STREAMIU, VipsStreamiu ))
#define VIPS_STREAMIU_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_STREAMIU, VipsStreamiuClass))
#define VIPS_IS_STREAMIU( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_STREAMIU ))
#define VIPS_IS_STREAMIU_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_STREAMIU ))
#define VIPS_STREAMIU_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_STREAMIU, VipsStreamiuClass ))

/* Subclass of streamiu with signals for handlers. This is supposed to be
 * useful for language bindings.
 */
typedef struct _VipsStreamiu {
	VipsStreami parent_object;

} VipsStreamiu;

typedef struct _VipsStreamiuClass {
	VipsStreamiClass parent_class;

	/* The action signals clients can use to implement read and seek.
	 * We must use gint64 everywhere since there's no G_TYPE_SIZE.
	 */

	gint64 (*read)( VipsStreamiu *, void *, gint64 );
	gint64 (*seek)( VipsStreamiu *, gint64, int );

} VipsStreamiuClass;

GType vips_streamiu_get_type( void );
VipsStreamiu *vips_streamiu_new( void );

#define VIPS_TYPE_STREAMO (vips_streamo_get_type())
#define VIPS_STREAMO( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_STREAMO, VipsStreamo ))
#define VIPS_STREAMO_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_STREAMO, VipsStreamoClass))
#define VIPS_IS_STREAMO( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_STREAMO ))
#define VIPS_IS_STREAMO_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_STREAMO ))
#define VIPS_STREAMO_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_STREAMO, VipsStreamoClass ))

/* PNG writes in 8kb chunks, so we need to be a little larger than that.
 */
#define VIPS_STREAMO_BUFFER_SIZE (8500)

/* Output to something like a socket, pipe or memory area. 
 */
typedef struct _VipsStreamo {
	VipsStream parent_object;

	/*< private >*/

	/* This stream should write to memory.
	 */
	gboolean memory;

	/* The stream has been finished and can no longer be written.
	 */
	gboolean finished;

	/* Write memory output here.
	 */
	GByteArray *memory_buffer;

	/* And return memory via this blob.
	 */
	VipsBlob *blob;

	/* Buffer small writes here. write_point is the index of the next
	 * character to write.
	 */
	unsigned char output_buffer[VIPS_STREAMO_BUFFER_SIZE];
	int write_point;

} VipsStreamo;

typedef struct _VipsStreamoClass {
	VipsStreamClass parent_class;

	/* Write to output. Args exactly as write(2).
	 */
	ssize_t (*write)( VipsStreamo *, const void *, size_t );

	/* Output has been generated, so do any clearing up,
	 * eg. copy the bytes we saved in memory to the stream blob.
	 */
	void (*finish)( VipsStreamo * );

} VipsStreamoClass;

GType vips_streamo_get_type( void );

VipsStreamo *vips_streamo_new_to_descriptor( int descriptor );
VipsStreamo *vips_streamo_new_to_filename( const char *filename );
VipsStreamo *vips_streamo_new_to_memory( void );
int vips_streamo_write( VipsStreamo *streamo, const void *data, size_t length );
void vips_streamo_finish( VipsStreamo *streamo );
unsigned char *vips_streamo_steal( VipsStreamo *streamo, size_t *length );
char *vips_streamo_steal_text( VipsStreamo *streamo );

int vips_streamo_putc( VipsStreamo *streamo, int ch );
#define VIPS_STREAMO_PUTC( S, C ) ( \
	(S)->write_point < VIPS_STREAMO_BUFFER_SIZE ? \
	((S)->output_buffer[(S)->write_point++] = (C), 0) : \
	vips_streamo_putc( (S), (C) ) \
)
int vips_streamo_writes( VipsStreamo *streamo, const char *str );
int vips_streamo_writef( VipsStreamo *streamo, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
int vips_streamo_write_amp( VipsStreamo *streamo, const char *str );

#define VIPS_TYPE_STREAMOU (vips_streamou_get_type())
#define VIPS_STREAMOU( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_STREAMOU, VipsStreamou ))
#define VIPS_STREAMOU_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_STREAMOU, VipsStreamouClass))
#define VIPS_IS_STREAMOU( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_STREAMOU ))
#define VIPS_IS_STREAMOU_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_STREAMOU ))
#define VIPS_STREAMOU_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_STREAMOU, VipsStreamouClass ))

#define VIPS_STREAMOU_BUFFER_SIZE (4096)

/* Output to something like a socket, pipe or memory area. 
 */
typedef struct _VipsStreamou {
	VipsStreamo parent_object;

} VipsStreamou;

typedef struct _VipsStreamouClass {
	VipsStreamoClass parent_class;

	/* The action signals clients can use to implement write and finish.
	 * We must use gint64 everywhere since there's no G_TYPE_SIZE.
	 */

	gint64 (*write)( VipsStreamou *, const void *, gint64 );
	void (*finish)( VipsStreamou * );

} VipsStreamouClass;

GType vips_streamou_get_type( void );
VipsStreamou *vips_streamou_new( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_STREAM_H*/
