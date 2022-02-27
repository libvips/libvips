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
#include <glib/gi18n-lib.h>

#include <string.h>

#include <vips/vips.h>

/**
 * vips_dbuf_init:
 * @dbuf: the buffer
 *
 * Initialize @dbuf.
 */
void
vips_dbuf_init( VipsDbuf *dbuf )
{
	dbuf->data = NULL;
	dbuf->allocated_size = 0;
	dbuf->data_size = 0;
	dbuf->write_point = 0;
}

/**
 * vips_dbuf_minimum_size:
 * @dbuf: the buffer
 * @size: the minimum size 
 *
 * Make sure @dbuf is at least @size bytes.
 * 
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
gboolean
vips_dbuf_minimum_size( VipsDbuf *dbuf, size_t size )
{
	if( size > dbuf->allocated_size ) { 
		const size_t new_allocated_size = 3 * (16 + size) / 2;

		unsigned char *new_data;

		if( !(new_data = 
			g_try_realloc( dbuf->data, new_allocated_size )) ) {
			vips_error( "VipsDbuf", "%s", _( "out of memory" ) );
			return( FALSE );
		}

		dbuf->data = new_data;
		dbuf->allocated_size = new_allocated_size;
	}

	return( TRUE ); 
}

/**
 * vips_dbuf_allocate:
 * @dbuf: the buffer
 * @size: the size to allocate
 *
 * Make sure @dbuf has at least @size bytes available after the write point.
 * 
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
gboolean
vips_dbuf_allocate( VipsDbuf *dbuf, size_t size )
{
	return( vips_dbuf_minimum_size( dbuf, dbuf->write_point + size ) ); 
}

/**
 * vips_dbuf_read:
 * @dbuf: the buffer
 * @data: read to this area
 * @size: read up to this many bytes
 *
 * Up to @size bytes are read from the buffer and copied to @data. The number
 * of bytes transferred is returned.
 *
 * Returns: the number of bytes transferred.
 */
size_t
vips_dbuf_read( VipsDbuf *dbuf, unsigned char *data, size_t size )
{
	const size_t available = dbuf->data_size - dbuf->write_point;
	const size_t copied = VIPS_MIN( size, available );

	memcpy( data, dbuf->data + dbuf->write_point, copied );
	dbuf->write_point += copied;

	return( copied );
}

/**
 * vips_dbuf_get_write:
 * @dbuf: the buffer
 * @size: (allow-none): optionally return length in bytes here
 *
 * Return a pointer to an area you can write to, return length of area in
 * @size. Use vips_dbuf_allocate() before this call to set a minimum amount of
 * space to have available. 
 *
 * The write point moves to just beyond the returned block. Use
 * vips_dbuf_seek() to move it back again.
 * 
 * Returns: (transfer none): start of write area.
 */
unsigned char *
vips_dbuf_get_write( VipsDbuf *dbuf, size_t *size )
{
	unsigned char *write = dbuf->data + dbuf->write_point;
	const size_t available = dbuf->allocated_size - dbuf->write_point;

	memset( write, 0, available ); 
	dbuf->write_point = dbuf->allocated_size;
	dbuf->data_size = dbuf->allocated_size;

	if( size )
		*size = available;

	return( write ); 
}

/**
 * vips_dbuf_write:
 * @dbuf: the buffer
 * @data: the data to write to the buffer
 * @size: the size of the len to write
 *
 * Append @size bytes from @data. @dbuf expands if necessary. 
 * 
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
gboolean
vips_dbuf_write( VipsDbuf *dbuf, const unsigned char *data, size_t size )
{
	if( !vips_dbuf_allocate( dbuf, size ) )
		return( FALSE ); 

	memcpy( dbuf->data + dbuf->write_point, data, size );
	dbuf->write_point += size;
	dbuf->data_size = VIPS_MAX( dbuf->data_size, dbuf->write_point );

	return( TRUE ); 
}

/**
 * vips_dbuf_writef:
 * @dbuf: the buffer
 * @fmt: <function>printf()</function>-style format string
 * @...: arguments to format string
 *
 * Format the string and write to @dbuf. 
 * 
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
gboolean
vips_dbuf_writef( VipsDbuf *dbuf, const char *fmt, ... )
{
	va_list ap;
	char *line;

        va_start( ap, fmt );
	line = g_strdup_vprintf( fmt, ap ); 
        va_end( ap );

	if( vips_dbuf_write( dbuf, (unsigned char *) line, strlen( line ) ) ) {
		g_free( line ); 
		return( FALSE );
	}
	g_free( line ); 

	return( TRUE ); 
}

/**
 * vips_dbuf_write_amp: 
 * @dbuf: the buffer
 * @str: string to write
 *
 * Write @str to @dbuf, but escape stuff that xml hates in text. Our
 * argument string is utf-8.
 *
 * XML rules:
 *
 * - We must escape &<> 
 * - Don't escape \n, \t, \r
 * - Do escape the other ASCII codes. 
 *
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
gboolean
vips_dbuf_write_amp( VipsDbuf *dbuf, const char *str )
{
	const char *p;

	for( p = str; *p; p++ ) 
		if( *p < 32 &&
			*p != '\n' &&
			*p != '\t' &&
			*p != '\r' ) {
			/* You'd think we could output "&#x02%x;", but xml
			 * 1.0 parsers barf on that. xml 1.1 allows this, but
			 * there are almost no parsers. 
			 *
			 * U+2400 onwards are unicode glyphs for the ASCII 
			 * control characters, so we can use them -- thanks
			 * electroly.
			 */
			if( !vips_dbuf_writef( dbuf, "&#x%04x;", 0x2400 + *p ) )
			       return( FALSE );	
		}
		else if( *p == '<' ) {
			if( !vips_dbuf_write( dbuf, (guchar *) "&lt;", 4 ) )
				return( FALSE );
		}
		else if( *p == '>' ) {
			if( !vips_dbuf_write( dbuf, (guchar *) "&gt;", 4 ) )
				return( FALSE );
		}
		else if( *p == '&' ) {
			if( !vips_dbuf_write( dbuf, (guchar *) "&amp;", 5 ) )
				return( FALSE );
		}
		else  {
			if( !vips_dbuf_write( dbuf, (guchar *) p, 1 ) )
				return( FALSE );
		}

	return( TRUE ); 
}

/**
 * vips_dbuf_reset:
 * @dbuf: the buffer
 *
 * Reset the buffer to empty. No memory is freed, just the data size and
 * write point are reset.
 */
void
vips_dbuf_reset( VipsDbuf *dbuf )
{
	dbuf->write_point = 0;
	dbuf->data_size = 0;
}

/**
 * vips_dbuf_destroy:
 * @dbuf: the buffer
 *
 * Destroy @dbuf. This frees any allocated memory.
 */
void
vips_dbuf_destroy( VipsDbuf *dbuf )
{
	vips_dbuf_reset( dbuf ); 

	VIPS_FREE( dbuf->data ); 
	dbuf->allocated_size = 0;
}

/**
 * vips_dbuf_seek:
 * @dbuf: the buffer
 * @offset: how to move the write point
 * @whence: from start, from end, from current
 *
 * Move the write point. @whence can be %SEEK_SET, %SEEK_CUR, %SEEK_END, with 
 * the usual meaning. 
 */
gboolean
vips_dbuf_seek( VipsDbuf *dbuf, off_t offset, int whence )
{
	off_t new_write_point;

	switch( whence ) {
	case SEEK_SET:
		new_write_point = offset; 
		break;

	case SEEK_END:
		new_write_point = dbuf->data_size + offset; 
		break;

	case SEEK_CUR:
		new_write_point = dbuf->write_point + offset; 
		break;

	default:
		g_assert( 0 ); 
		new_write_point = dbuf->write_point; 
		break;
	}

	if( new_write_point < 0 ) {
		vips_error( "VipsDbuf", "%s", "negative seek" ); 
		return( FALSE );
	}

	/* Possibly need to grow the buffer
	 */
	if( !vips_dbuf_minimum_size( dbuf, new_write_point ) )
		return( FALSE ); 
	dbuf->write_point = new_write_point; 
	if( dbuf->data_size < dbuf->write_point ) { 
		memset( dbuf->data + dbuf->data_size, 0, 
			dbuf->write_point - dbuf->data_size ); 
		dbuf->data_size = dbuf->write_point;
	}

	return( TRUE ); 
}

/**
 * vips_dbuf_truncate:
 * @dbuf: the buffer
 *
 * Truncate the data so that it ends at the write point. No memory is freed. 
 */
void
vips_dbuf_truncate( VipsDbuf *dbuf )
{
	dbuf->data_size = dbuf->write_point;
}

/**
 * vips_dbuf_tell:
 * @dbuf: the buffer
 *
 * Returns: the current write point
 */
off_t
vips_dbuf_tell( VipsDbuf *dbuf )
{
	return( dbuf->write_point ); 
}

/**
 * vips_dbuf_null_terminate:
 * @dbuf: the buffer
 *
 * Make sure the byte after the last data byte is `\0`. This extra byte is not
 * included in the data size and the write point is not moved.
 *
 * This makes it safe to treat the dbuf contents as a C string. 
 * 
 * Returns: %FALSE on out of memory, %TRUE otherwise.
 */
static gboolean
vips_dbuf_null_terminate( VipsDbuf *dbuf )
{
	if( !vips_dbuf_minimum_size( dbuf, dbuf->data_size + 1 ) )
		return( FALSE );

	dbuf->data[dbuf->data_size] = 0;

	return( TRUE ); 
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

	vips_dbuf_null_terminate( dbuf ); 

	data = dbuf->data;

	if( size )
		*size = dbuf->data_size;

	dbuf->data = NULL;
	vips_dbuf_destroy( dbuf );

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
	vips_dbuf_null_terminate( dbuf ); 

	if( size )
		*size = dbuf->data_size;

	return( dbuf->data ); 
}


