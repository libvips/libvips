/* A byte sink .. it can be a pipe, socket, memory, or subclass or add hooks
 * to join it to something else.
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

#ifndef VIPS_OSTREAM_H
#define VIPS_OSTREAM_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_OSTREAM (vips_ostream_get_type())
#define VIPS_OSTREAM( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_OSTREAM, VipsOstream ))
#define VIPS_OSTREAM_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_OSTREAM, VipsOstreamClass))
#define VIPS_IS_OSTREAM( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_OSTREAM ))
#define VIPS_IS_OSTREAM_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_OSTREAM ))
#define VIPS_OSTREAM_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_OSTREAM, VipsOstreamClass ))

/* Write to something like a socket, pipe or memory area. 
 */
typedef struct _VipsOstream {
	VipsOstream parent_object;

	/*< private >*/

	/* A descriptor we close with vips_tracked_close().
	 */
	int tracked_descriptor;	

	/* A descriptor we close with close().
	 */
	int close_descriptor;	

	/* Read/write this fd if connected to a system pipe/socket.
	 */
	int descriptor;	

	/* If descriptor is a file, the filename we opened. Handy for error
	 * messages. 
	 */
	char *filename; 

	/* Write memory output here.
	 */
	GByteArray *memory;

	/* And return memory via this blob.
	 */
	VipsBlob *blob;

} VipsOstream;

typedef struct _VipsOstreamClass {
	VipsOstreamClass parent_class;

	/* If defined, output some bytes with this. Otherwise use write().
	 */
	ssize_t (*write)( VipsOstream *, const unsigned char *, size_t );

	/* A complete output image has been generated, so do any clearing up,
	 * eg. copy the bytes we saved in memory to the output blob.
	 */
	void (*finish)( VipsOstream * );

} VipsOstreamClass;

GType vips_ostream_get_type( void );

VipsOstream *vips_ostream_new_from_descriptor( int descriptor );
VipsOstream *vips_ostream_new_from_filename( const char *filename );
VipsOstream *vips_ostream_new_memory( void );
int vips_ostream_write( VipsOstream *output,
	const unsigned char *data, size_t length );
void vips_ostream_finish( VipsOstream *output );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_OSTREAM_H*/
