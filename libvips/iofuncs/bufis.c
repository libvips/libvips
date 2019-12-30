/* Buffered input from a source.
 *
 * J.Cupitt, 18/11/19
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

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <ctype.h>
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

G_DEFINE_TYPE( VipsBufis, vips_bufis, VIPS_TYPE_OBJECT );

static void
vips_bufis_class_init( VipsBufisClass *class )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "bufis";
	object_class->description = _( "buffered source" );

	VIPS_ARG_OBJECT( class, "input", 1,
		_( "Input" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsBufis, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_bufis_init( VipsBufis *bufis )
{
	bufis->read_point = 0;
	bufis->chars_in_buffer = 0;
	bufis->input_buffer[0] = '\0';
}

/**
 * vips_bufis_new_from_source:
 * @source: source to operate on
 *
 * Create a bufis wrapping a source. 
 *
 * Returns: a new #VipsBufis
 */
VipsBufis *
vips_bufis_new_from_source( VipsSource *source )
{
	VipsBufis *bufis;

	bufis = VIPS_BUFIS( g_object_new( VIPS_TYPE_BUFIS, 
		"input", source,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( bufis ) ) ) {
		VIPS_UNREF( bufis );
		return( NULL );
	}

	return( bufis ); 
}

/**
 * vips_bufis_unbuffer:
 * @bufis: source to operate on
 *
 * Discard the input buffer and reset the read point. You must call this
 * before using read or seek on the underlying #VipsSource class.
 */
void
vips_bufis_unbuffer( VipsBufis *bufis )
{
	/* We'd read ahead a little way -- seek backwards by that amount.
	 */
	vips_source_seek( bufis->source, 
		bufis->read_point - bufis->chars_in_buffer, SEEK_CUR );
	bufis->read_point = 0;
	bufis->chars_in_buffer = 0;
}

/* Returns -1 on error, 0 on EOF, otherwise bytes read.
 */
static gint64
vips_bufis_refill( VipsBufis *bufis )
{
	gint64 bytes_read;

	VIPS_DEBUG_MSG( "vips_bufis_refill:\n" );

	/* We should not discard any unread bytes.
	 */
	g_assert( bufis->read_point == bufis->chars_in_buffer );

	bytes_read = vips_source_read( bufis->source, 
		bufis->input_buffer, VIPS_BUFIS_BUFFER_SIZE );
	if( bytes_read == -1 )
		return( -1 );

	bufis->read_point = 0;
	bufis->chars_in_buffer = bytes_read;
	
	/* Always add a null byte so we can use strchr() etc. on lines. This is 
	 * safe because input_buffer is VIPS_BUFIS_BUFFER_SIZE + 1 bytes.
	 */
	bufis->input_buffer[bytes_read] = '\0';

	return( bytes_read );
}

/**
 * vips_bufis_getc:
 * @bufis: source to operate on
 *
 * Fetch the next character from the source. 
 *
 * If you can, use the macro VIPS_BUFIS_GETC() instead for speed.
 *
 * Returns: the next char from @bufis, -1 on read error or EOF.
 */
int
vips_bufis_getc( VipsBufis *bufis )
{
	if( bufis->read_point == bufis->chars_in_buffer &&
		vips_bufis_refill( bufis ) <= 0 )
		return( -1 );

	g_assert( bufis->read_point < bufis->chars_in_buffer );

	return( bufis->input_buffer[bufis->read_point++] );
}

/** 
 * VIPS_BUFIS_GETC:
 * @bufis: source to operate on
 *
 * Fetch the next character from the source. 
 *
 * Returns: the next char from @bufis, -1 on read error or EOF.
 */

/**
 * vips_bufis_ungetc:
 * @bufis: source to operate on
 *
 * The opposite of vips_bufis_getc(): undo the previous getc.
 *
 * unget more than one character is undefined. Unget at the start of the file 
 * does nothing.
 *
 * If you can, use the macro VIPS_BUFIS_UNGETC() instead for speed.
 */
void
vips_bufis_ungetc( VipsBufis *bufis )
{
	if( bufis->read_point > 0 ) 
		bufis->read_point -= 1;
}

/**
 * VIPS_BUFIS_UNGETC:
 * @bufis: source to operate on
 *
 * The opposite of vips_bufis_getc(): undo the previous getc.
 *
 * unget more than one character is undefined. Unget at the start of the file 
 * does nothing.
 */

/**
 * vips_bufis_require:
 * @bufis: source to operate on
 * @require: make sure we have at least this many chars available
 *
 * Make sure there are at least @require bytes of readahead available.
 *
 * Returns: 0 on success, -1 on error or EOF.
 */
int
vips_bufis_require( VipsBufis *bufis, int require )
{
	g_assert( require < VIPS_BUFIS_BUFFER_SIZE ); 
	g_assert( bufis->chars_in_buffer >= 0 );
	g_assert( bufis->chars_in_buffer <= VIPS_BUFIS_BUFFER_SIZE );
	g_assert( bufis->read_point >= 0 ); 
	g_assert( bufis->read_point <= bufis->chars_in_buffer );

	VIPS_DEBUG_MSG( "vips_bufis_require: %d\n", require );

	if( bufis->read_point + require > bufis->chars_in_buffer ) {
		/* Areas can overlap, so we must memmove().
		 */
		memmove( bufis->input_buffer, 
			bufis->input_buffer + bufis->read_point,
			bufis->chars_in_buffer - bufis->read_point );
		bufis->chars_in_buffer -= bufis->read_point;
		bufis->read_point = 0;

		while( require > bufis->chars_in_buffer ) {
			unsigned char *to = bufis->input_buffer + 
				bufis->chars_in_buffer;
			int space_available = 
				VIPS_BUFIS_BUFFER_SIZE - 
				bufis->chars_in_buffer;
			size_t bytes_read;

			if( (bytes_read = vips_source_read( bufis->source,
				to, space_available )) == -1 )
				return( -1 );
			if( bytes_read == 0 ) { 
				vips_error( 
					vips_connection_nick( VIPS_CONNECTION( 
						bufis->source ) ), 
					"%s", _( "end of file" ) ); 
				return( -1 );
			}

			to[bytes_read] = '\0';
			bufis->chars_in_buffer += bytes_read;
		}
	}

	return( 0 );
}

/** 
 * VIPS_BUFIS_REQUIRE:
 * @bufis: source to operate on
 * @require: need this many characters
 *
 * Make sure at least @require characters are available for 
 * VIPS_BUFIS_PEEK() and VIPS_BUFIS_FETCH().
 *
 * Returns: 0 on success, -1 on read error or EOF.
 */

/** 
 * VIPS_BUFIS_PEEK:
 * @bufis: source to operate on
 *
 * After a successful VIPS_BUFIS_REQUIRE(), you can index this to get
 * require characters of input.
 *
 * Returns: a pointer to the next requre characters of input.
 */

/** 
 * VIPS_BUFIS_FETCH:
 * @bufis: source to operate on
 *
 * After a successful VIPS_BUFIS_REQUIRE(), you can use this require times
 * to fetch characters of input.
 *
 * Returns: the next input character.
 */

/**
 * vips_bufis_get_line:
 * @bufis: source to operate on
 *
 * Fetch the next line of text from @bufis and return it. The end of 
 * line character (or characters, for DOS files) are removed, and the string
 * is terminated with a null (`\0` character).
 *
 * Returns NULL on end of file or read error.
 *
 * If the line is longer than some arbitrary (but large) limit, it is
 * truncated. If you need to be able to read very long lines, use the
 * slower vips_bufis_get_line_copy().
 *
 * The return value is owned by @bufis and must not be freed. It 
 * is valid until the next get call to @bufis.
 *
 * Returns: the next line of text, or NULL on EOF or read error.
 */
const char *
vips_bufis_get_line( VipsBufis *bufis )
{
	int write_point;
	int space_remaining;
	int ch;

	VIPS_DEBUG_MSG( "vips_bufis_get_line:\n" );

	write_point = 0;
	space_remaining = VIPS_BUFIS_BUFFER_SIZE;

	while( (ch = VIPS_BUFIS_GETC( bufis )) != -1 &&
		ch != '\n' &&
		space_remaining > 0 ) {
		bufis->line[write_point] = ch;
		write_point += 1;
		space_remaining -= 1;
	}
	bufis->line[write_point] = '\0';

	/* If we hit EOF immediately, return EOF.
	 */
	if( ch == -1 && 
		write_point == 0 )
		return( NULL );

	/* If the final char in the buffer is \r, this is probably a DOS file 
	 * and we should remove that too. 
	 *
	 * There's a chance this could incorrectly remove \r in very long 
	 * lines, but ignore this.
	 */
	if( write_point > 0 &&
		bufis->line[write_point - 1] == '\r' )
		bufis->line[write_point - 1] = '\0';

	/* If we filled the output line without seeing \n, keep going to the
	 * next \n.
	 */
	if( ch != '\n' &&
		space_remaining == 0 ) {
		while( (ch = VIPS_BUFIS_GETC( bufis )) != -1 &&
			ch != '\n' ) 
			;
	}

	VIPS_DEBUG_MSG( "    %s\n", bufis->line );

	return( (const char *) bufis->line );
}

/**
 * vips_bufis_get_line_copy:
 * @bufis: source to operate on
 *
 * Fetch the next line of text from @bufis and return it. The end of 
 * line character (or characters, for DOS files) are removed, and the string
 * is terminated with a null (`\0` character).
 *
 * The return result must be freed with g_free().
 *
 * This is slower than vips_bufis_get_line(), but can work with lines of
 * any length.
 *
 * Returns: the next line of text, or NULL on EOF or read error.
 */
char *
vips_bufis_get_line_copy( VipsBufis *bufis )
{
	static const unsigned char null = '\0';

	VIPS_DEBUG_MSG( "vips_bufis_get_line_copy:\n" );

	GByteArray *buffer;
	int ch;
	char *result;

	buffer = g_byte_array_new();

	while( (ch = VIPS_BUFIS_GETC( bufis )) != -1 &&
		ch != '\n' ) {
		unsigned char c = ch;

		g_byte_array_append( buffer, &c, 1 );
	}

	/* Immediate EOF.
	 */
	if( ch == -1 &&
		buffer->len == 0 ) {
		VIPS_FREEF( g_byte_array_unref, buffer ); 
		return( NULL );
	}

	/* If the character before the \n was \r, this is probably a DOS file
	 * and we should remove the \r.
	 */
	if( ch == '\n' &&
		buffer->len > 0 &&
		buffer->data[buffer->len - 1] == '\r' )
		g_byte_array_set_size( buffer, buffer->len - 1 );

	g_byte_array_append( buffer, &null, 1 );

	result = (char *) g_byte_array_free( buffer, FALSE );

	VIPS_DEBUG_MSG( "    %s\n", result );

	return( result );
}

/**
 * vips_bufis_get_non_whitespace:
 * @bufis: source to operate on
 *
 * Fetch the next chunk of non-whitespace text from the source, and
 * null-terminate it. 
 *
 * After this, the next getc will be the first char of the next block of
 * whitespace (or EOF). 
 *
 * If the first getc is whitespace, stop instantly and return the empty
 * string.
 *
 * If the item is longer than some arbitrary (but large) limit, it is
 * truncated. 
 *
 * The return value is owned by @bufis and must not be freed. It 
 * is valid until the next get call to @bufis.
 *
 * Returns: the next block of non-whitespace, or NULL on EOF or read error.
 */
const char *
vips_bufis_get_non_whitespace( VipsBufis *bufis )
{
	int ch;
	int i;

	for( i = 0; i < VIPS_BUFIS_BUFFER_SIZE &&
		!isspace( ch = VIPS_BUFIS_GETC( bufis ) ) &&
		ch != EOF; i++ ) 
		bufis->line[i] = ch;
	bufis->line[i] = '\0';

	/* If we stopped before seeing any whitespace, skip to the end of the
	 * block of non-whitespace.
	 */
	if( !isspace( ch ) ) 
		while( !isspace( ch = VIPS_BUFIS_GETC( bufis ) ) &&
			ch != EOF )
			;

	/* If we finally stopped on whitespace, step back one so the next get
	 * will be whitespace (or EOF).
	 */
	if( isspace( ch ) ) 
		VIPS_BUFIS_UNGETC( bufis );

	return( (const char *) bufis->line );
}

/**
 * vips_bufis_skip_whitespace:
 * @bufis: source to operate on
 *
 * After this, the next getc will be the first char of the next block of
 * non-whitespace (or EOF).
 *
 * Also skip comments, ie. from any '#' character to the end of the line.
 *
 * Returns: 0 on success, or -1 on EOF.
 */
int 
vips_bufis_skip_whitespace( VipsBufis *bufis )
{
	int ch;

	do {
		ch = VIPS_BUFIS_GETC( bufis );

		/* # skip comments too.
		 */
		if( ch == '#' ) {
			/* Probably EOF. 
			 */
			if( !vips_bufis_get_line( bufis ) ) 
				return( -1 );
			ch = VIPS_BUFIS_GETC( bufis );
		}
	} while( isspace( ch ) );

	VIPS_BUFIS_UNGETC( bufis );

	return( 0 );
}
