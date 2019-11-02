/* A layer over streami to provide buffered and line-based input.
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

/* TODO
 *
 * - make something to parse input and implement rad load
 * - gaussblur is missing the vector path again argh
 * - can we map and then close the fd? how about on Windows?
 * - make a subclass that lets you set vfuncs as params, inc. close(),
 *   is_pipe etc.
 */

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

G_DEFINE_TYPE( VipsStreamib, vips_streamib, VIPS_TYPE_OBJECT );

static void
vips_streamib_class_init( VipsStreamibClass *class )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "streamib";
	object_class->description = _( "buffered input stream" );

	VIPS_ARG_OBJECT( class, "input", 1,
		_( "Input" ),
		_( "Stream to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsStreamib, streami ),
		VIPS_TYPE_STREAMI );

}

static void
vips_streamib_init( VipsStreamib *streamib )
{
	streamib->read_point = streamib->input_buffer;
	streamib->bytes_remaining = 0;
	streamib->read_point[streamib->bytes_remaining] = '\0';
}

/**
 * vips_streamib_new:
 * @streami: stream to operate on
 *
 * Create a streamib wrapping a streami. 
 *
 * Returns: a new #VipsStreamib
 */
VipsStreamib *
vips_streamib_new( VipsStreami *streami )
{
	VipsStreamib *streamib;

	streamib = VIPS_STREAMIB( g_object_new( VIPS_TYPE_STREAMIB, 
		"input", streami,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( streamib ) ) ) {
		VIPS_UNREF( streamib );
		return( NULL );
	}

	return( streamib ); 
}

/**
 * vips_streamib_unbuffer:
 * @streamib: stream to operate on
 *
 * Discard the input buffer and reset the read point. You must call this
 * before using read or seek on the underlying #VipsStreami class.
 */
void
vips_streamib_unbuffer( VipsStreamib *streamib )
{
	int bytes_in_buffer = streamib->read_point - streamib->input_buffer;

	streamib->read_point = streamib->input_buffer;
	streamib->bytes_remaining = 0;
	vips_streami_seek( streamib->streami, 
		-bytes_in_buffer, SEEK_SET );
}

/* Returns -1 on error, 0 on EOF, otherwise bytes read.
 */
static ssize_t
vips_streamib_refill( VipsStreamib *streamib )
{
	ssize_t bytes_read;

	/* We should not discard any unread bytes.
	 */
	g_assert( streamib->bytes_remaining == 0 );

	bytes_read = vips_streami_read( streamib->streami, 
		streamib->input_buffer, VIPS_STREAMIB_BUFFER_SIZE );
	if( bytes_read == -1 )
		return( -1 );

	streamib->read_point = streamib->input_buffer;
	streamib->bytes_remaining = bytes_read;
	
	/* Always add a null byte so we can use strchr() etc. on lines. This is 
	 * safe because input_buffer is VIPS_STREAMIB_BUFFER_SIZE + 1 bytes.
	 */
	streamib->read_point[bytes_read] = '\0';

	return( bytes_read );
}

/**
 * vips_streamib_getc:
 * @streamib: stream to operate on
 *
 * Fetch the next character from the stream. 
 *
 * Use the macro VIPS_STREAMIB_GETC() instead for speed.
 *
 * Returns: the next char from @streamib, -1 on read error or EOF.
 */
int
vips_streamib_getc( VipsStreamib *streamib )
{
	int ch;

	if( streamib->bytes_remaining == 0 &&
		vips_streamib_refill( streamib ) <= 0 )
		return( -1 );

	ch = streamib->read_point[0];

	streamib->read_point += 1;
	streamib->bytes_remaining -= 1;

	return( ch );
}

/** VIPS_STREAMIB_GETC:
 * @streamib: stream to operate on
 *
 * Fetch the next character from the stream. 
 *
 * Returns: the next char from @streamib, -1 on read error or EOF.
 */

/**
 * vips_streamib_ungetc:
 * @streamib: stream to operate on
 *
 * The opposite of vips_streamib_getc(): undo the previous getc.
 *
 * unget more than one character is undefined. Unget at the start of the file 
 * does nothing.
 */
void
vips_streamib_ungetc( VipsStreamib *streamib )
{
	if( streamib->read_point > streamib->input_buffer ) {
		streamib->read_point -= 1;
		streamib->bytes_remaining += 1;
	}
}

/**
 * vips_streamib_get_line:
 * @streamib: stream to operate on
 * @line: return the next line of text here
 *
 * Fetch the next line of text from @streamib and return in @line. The end of 
 * line character (or characters, for DOS files) are removed, and @line 
 * is terminated with a null (`\0` character).
 *
 * @line is set to NULL on end of file.
 *
 * If the line is longer than some arbitrary (but large) limit, is is
 * truncated. If you need to be able to read very long lines, use the
 * slower vips_streamib_get_line_copy().
 *
 * The return value of @line is owned by @streamib and must not be freed. It 
 * is valid until the next call to vips_streamib_get_line().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_streamib_get_line( VipsStreamib *streamib, const char **line ) 
{
	char *write_point;
	int space_remaining;
	int ch;

	write_point = streamib->line;
	space_remaining = VIPS_STREAMIB_BUFFER_SIZE;

	while( (ch = VIPS_STREAMIB_GETC( streamib )) != -1 &&
		ch != '\n' &&
		space_remaining > 0 ) {
		write_point[0] = ch;
		write_point += 1;
		space_remaining -= 1;
	}
	write_point[0] = '\0';

	/* If we hit EOF immediately, return EOF.
	 */
	if( write_point == streamib->line ) {
		*line = NULL;
		return( 0 );
	}

	/* If we filled the output line without seeing \n, keep going to the
	 * next \n.
	 */
	if( ch != '\n' &&
		space_remaining == 0 ) {
		while( (ch = VIPS_STREAMIB_GETC( streamib )) != -1 &&
			ch != '\n' ) 
			;
	}

	/* If we stopped on \n, try to skip any \r too.
	 */
	if( ch == '\n' ) {
		if( VIPS_STREAMIB_GETC( streamib ) != '\r' )
			vips_streamib_ungetc( streamib );
	}

	*line = streamib->line;

	return( 0 );
}

/**
 * vips_streamib_get_line_copy:
 * @streamib: stream to operate on
 *
 * Return the next line of text from the stream. The newline character (or
 * characters) are removed, and and the string is terminated with a null
 * (`\0` character).
 *
 * The return result must be freed with g_free().
 *
 * This is slower than vips_streamib_get_line(), but can work with lines of
 * any length.
 *
 * Returns: the next line from the file, or NULL on EOF.
 *
 */
int
vips_streamib_get_line_copy( VipsStreamib *streamib, char **line ) 
{
	const unsigned char null = '\0';
	GByteArray *buffer;
	int ch;

	buffer = g_byte_array_new();

	while( (ch = VIPS_STREAMIB_GETC( streamib )) != -1 &&
		ch != '\n' ) {
		unsigned char c = ch;

		g_byte_array_append( buffer, &c, 1 );
	}

	if( ch == -1 ) {
		VIPS_FREEF( g_byte_array_unref, buffer ); 
		return( -1 );
	}

	g_byte_array_append( buffer, &null, 1 );

	/* If we stopped on \n, try to skip any \r too.
	 */
	if( ch == '\n' ) {
		if( VIPS_STREAMIB_GETC( streamib ) != '\r' )
			vips_streamib_ungetc( streamib );
	}

	*line = (char *) g_byte_array_free( buffer, FALSE );

	return( 0 );
}
