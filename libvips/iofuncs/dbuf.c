/* A dynamic memory buffer that expands as you write.
 */

/*

    Copyright (C) 1991-2003 The National Gallery

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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <string.h>

#include <vips/vips.h>

/**
 * vips_dbuf_init:
 * @dbuf: the buffer
 *
 * Initialize a buffer.
 */
void
vips_dbuf_init( VipsDbuf *dbuf )
{
	dbuf->data = NULL;
	dbuf->max_size = 0;
	dbuf->write_point = 0;
}

/**
 * vips_dbuf_allocate:
 * @dbuf: the buffer
 * @size: the size to allocate
 *
 * Make sure @dbuf has at least @size bytes available for writing.
 * 
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
gboolean
vips_dbuf_allocate( VipsDbuf *dbuf, size_t size )
{
	size_t new_write_point = dbuf->write_point + size;

	if( new_write_point > dbuf->max_size ) { 
		size_t new_max_size = 3 * (16 + new_write_point) / 2;

		unsigned char *new_data;

		if( !(new_data = g_try_realloc( dbuf->data, new_max_size )) ) {
			vips_error( "VipsDbuf", "%s", _( "out of memory" ) );
			return( FALSE );
		}

		dbuf->data = new_data;
		dbuf->max_size = new_max_size;
	}

	return( TRUE ); 
}

/**
 * vips_dbuf_get_write:
 * @dbuf: the buffer
 * @size: (allow-none): optionally return length in bytes here
 *
 * Return a pointer to an area you can write to, return length of area in
 * @size. Use vips_dbuf_allocate() before this call to make the space.
 * 
 * Returns: (transfer none): start of write area.
 */
unsigned char *
vips_dbuf_get_write( VipsDbuf *dbuf, size_t *size )
{
	unsigned char *data = dbuf->data + dbuf->write_point;

	if( size )
		*size = dbuf->max_size - dbuf->write_point;

	dbuf->write_point = dbuf->max_size;

	return( data ); 
}

/**
 * vips_dbuf_append:
 * @dbuf: the buffer
 * @data: the data to append to the buffer
 * @size: the size of the len to append
 *
 * Append len bytes from @data to the buffer. The buffer expands if necessary. 
 * 
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
gboolean
vips_dbuf_append( VipsDbuf *dbuf, const unsigned char *data, size_t size )
{
	if( !vips_dbuf_allocate( dbuf, size ) )
		return( FALSE ); 

	memcpy( dbuf->data + dbuf->write_point, data, size );
	dbuf->write_point += size;

	return( TRUE ); 
}

/**
 * vips_dbuf_appendf:
 * @dbuf: the buffer
 * @fmt: <function>printf()</function>-style format string
 * @...: arguments to format string
 *
 * Format the string and append to @dbuf. 
 * 
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
gboolean
vips_dbuf_appendf( VipsDbuf *dbuf, const char *fmt, ... )
{
	va_list ap;
	char *line;

        va_start( ap, fmt );
	line = g_strdup_vprintf( fmt, ap ); 
        va_end( ap );

	if( vips_dbuf_append( dbuf, (unsigned char *) line, strlen( line ) ) ) {
		g_free( line ); 
		return( FALSE );
	}
	g_free( line ); 

	return( TRUE ); 
}

/**
 * vips_dbuf_rewind:
 * @dbuf: the buffer
 *
 * Reset the buffer to empty. No memory is freed, just the write pointer is
 * reset.
 */
void
vips_dbuf_rewind( VipsDbuf *dbuf )
{
	dbuf->write_point = 0;
}

/**
 * vips_dbuf_destroy:
 * @dbuf: the buffer
 *
 * Destroy a buffer. This frees any allocated memory.
 */
void
vips_dbuf_destroy( VipsDbuf *dbuf )
{
	VIPS_FREE( dbuf->data ); 
	dbuf->max_size = 0;
	dbuf->write_point = 0;
}

/**
 * vips_dbuf_steal:
 * @dbuf: the buffer
 * @size: (allow-none): optionally return length in bytes here
 *
 * Destroy a buffer, but rather than freeing memory, a pointer is returned.
 * This must be freed with g_free().
 *
 * A `\0` is appended, but not included in the character count. This is so the
 * pointer can be safely treated as a C string. 
 *
 * Returns: (transfer full): The pointer held by @dbuf.
 */
unsigned char *
vips_dbuf_steal( VipsDbuf *dbuf, size_t *size )
{
	unsigned char *data;

	vips_dbuf_append( dbuf, (unsigned char *) "", 1 );
	dbuf->write_point -= 1;

	data = dbuf->data;

	if( size )
		*size = dbuf->write_point;

	dbuf->data = NULL;
	dbuf->max_size = 0;
	dbuf->write_point = 0;

	return( data ); 
}

/**
 * vips_dbuf_string:
 * @dbuf: the buffer
 * @size: (allow-none): optionally return length in bytes here
 *
 * Return a pointer to @dbuf's internal data.
 *
 * A `\0` is appended, but not included in the character count. This is so the
 * pointer can be safely treated as a C string. 
 *
 * Returns: (transfer none): The pointer held by @dbuf.
 */
unsigned char *
vips_dbuf_string( VipsDbuf *dbuf, size_t *size )
{
	vips_dbuf_append( dbuf, (unsigned char *) "", 1 );
	dbuf->write_point -= 1;

	if( size )
		*size = dbuf->write_point;

	return( dbuf->data ); 
}


