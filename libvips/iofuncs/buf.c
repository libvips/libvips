/* string buffers
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>

/**
 * SECTION: buf
 * @short_description: a string you can append to
 * @stability: Stable
 * @see_also: #vips
 * @include: vips/vips.h
 *
 * A message buffer you can append stuff to safely and quickly. If the message 
 * gets too long, you get "..." and truncation. Message buffers can be on the 
 * stack or heap.
 *
 * For example:
 *
 * |[
 * char txt[256];
 * VipsBuf buf = VIPS_BUF_STATIC (txt);
 * int i;
 *
 * vips_buf_appends (&buf, "Numbers are: ");
 * for (i = 0; i &lt; array_length; i++) {
 *   if (i &gt; 0)
 *     vips_buf_appends (&buf, ", ");
 *   vips_buf_appendg (&buf, array[i]);
 * }
 * printf ("%s", vips_buf_all (&buf));
 * ]|
 */

/** 
 * VIPS_BUF_STATIC:
 * @TEXT: the storage area to use
 *
 * Initialize a heap buffer. For example:
 *
 * |[
 * char txt[256];
 * VipsBuf buf = VIPS_BUF_STATIC (txt);
 * ]|
 */

/**
 * vips_buf_rewind:
 * @buf: the buffer
 *
 * Reset the buffer to the empty string.
 */
void
vips_buf_rewind( VipsBuf *buf )
{
	buf->i = 0;
	buf->lasti = 0;
	buf->full = FALSE;

	if( buf->base )
		buf->base[0] = '\0';
}

/**
 * vips_buf_init:
 * @buf: the buffer
 *
 * Initialize a buffer.
 */
void
vips_buf_init( VipsBuf *buf )
{
	buf->base = NULL;
	buf->mx = 0;
	buf->dynamic = FALSE;
	vips_buf_rewind( buf );
}

/**
 * vips_buf_destroy:
 * @buf: the buffer
 *
 * Destroy a buffer. Only needed for heap buffers. Leaves the buffer in the
 * _init state.
 */
void
vips_buf_destroy( VipsBuf *buf )
{
	if( buf->dynamic ) {
		VIPS_FREE( buf->base );
	}

	vips_buf_init( buf );
}

/** 
 * vips_buf_set_static:
 * @buf: the buffer
 * @base: the start of the memory area to use for storage
 * @mx: the size of the storage area
 *
 * Attach the buffer to a static memory area. The buffer needs to have been
 * initialised. The memory area needs to be at least 4 bytes long.
 */
void
vips_buf_set_static( VipsBuf *buf, char *base, int mx )
{
	g_assert( mx >= 4 );

	vips_buf_destroy( buf );

	buf->base = base;
	buf->mx = mx;
	buf->dynamic = FALSE;
	vips_buf_rewind( buf );
}

/**
 * vips_buf_init_static:
 * @buf: the buffer
 * @base: the start of the memory area to use for storage
 * @mx: the size of the storage area
 *
 * Initialise and attach to a static memory area. VIPS_BUF_STATIC() is usually
 * more convenient.
 *
 * For example:
 *
 * |[
 * char txt[256];
 * VipsBuf buf;
 * 
 * vips_buf_init_static (&buf, txt, 256);
 * ]|
 * 
 * Static buffers don't need to be freed when they go out of scope, but their
 * size must be set at compile-time.
 */
void
vips_buf_init_static( VipsBuf *buf, char *base, int mx )
{
	vips_buf_init( buf );
	vips_buf_set_static( buf, base, mx );
}

/**
 * vips_buf_set_dynamic:
 * @buf: the buffer
 * @mx: the size of the storage area
 *
 * Attach the buffer to a heap memory area. The buffer needs to have been
 * initialised. The memory area needs to be at least 4 bytes long.
 */
void
vips_buf_set_dynamic( VipsBuf *buf, int mx )
{
	g_assert( mx >= 4 );

	if( buf->mx == mx && buf->dynamic ) 
		/* No change?
		 */
		vips_buf_rewind( buf );
	else {
		vips_buf_destroy( buf );

		if( !(buf->base = VIPS_ARRAY( NULL, mx, char )) )
			/* No error return, so just block writes.
			 */
			buf->full = TRUE;
		else {
			buf->mx = mx;
			buf->dynamic = TRUE;
			vips_buf_rewind( buf );
		}
	}
}

/**
 * vips_buf_init_dynamic:
 * @buf: the buffer
 * @mx: the size of the storage area
 *
 * Initialise and attach to a heap memory area. 
 * The memory area needs to be at least 4 bytes long.
 * 
 * |[
 * VipsBuf buf;
 * 
 * vips_buf_init_synamic (&buf, 256);
 * ]|
 *
 * Dynamic buffers must be freed with vips_buf_destroy(), but their size can
 * be set at runtime.
 */
void
vips_buf_init_dynamic( VipsBuf *buf, int mx )
{
	vips_buf_init( buf );
	vips_buf_set_dynamic( buf, mx );
}

/**
 * vips_buf_appendns:
 * @buf: the buffer
 * @str: the string to append to the buffer
 * @sz: the size of the string to append
 *
 * Append at most @sz chars from @str to @buf. @sz < 0 means unlimited. This
 * is the low-level append operation: functions like vips_buf_appendf() build
 * on top of this.
 * 
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_appendns( VipsBuf *buf, const char *str, int sz )
{
	int len;
	int n;
	int avail;
	int cpy;

	if( buf->full )
		return( FALSE );

	/* Amount we want to copy.
	 */
	len = strlen( str );
	if( sz >= 0 )
		n = VIPS_MIN( sz, len );
	else
		n = len;

	/* Space available.
	 */
	avail = buf->mx - buf->i - 4;

	cpy = VIPS_MIN( n, avail );

	/* Can't use vips_strncpy() here, we don't want to drop the end of the
	 * string.
	 *
	 * gcc10.3 (I think?) issues a false-positive warning about this.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
	strncpy( buf->base + buf->i, str, cpy );
#pragma GCC diagnostic pop
	buf->i += cpy;

	if( buf->i >= buf->mx - 4 ) {
		buf->full = TRUE;
		strcpy( buf->base + buf->mx - 4, "..." );
		buf->i = buf->mx - 1;
		return( FALSE );
	}

	return( TRUE );
}

/**
 * vips_buf_appends:
 * @buf: the buffer
 * @str: the string to append to the buffer
 *
 * Append the whole of @str to @buf. 
 * 
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_appends( VipsBuf *buf, const char *str )
{
	return( vips_buf_appendns( buf, str, -1 ) );
}

/**
 * vips_buf_appendc:
 * @buf: the buffer
 * @ch: the character to append to the buffer
 *
 * Append a single character @ch to @buf. 
 * 
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_appendc( VipsBuf *buf, char ch )
{
	char tiny[2];

	tiny[0] = ch;
	tiny[1] = '\0';

	return( vips_buf_appendns( buf, tiny, 1 ) );
}

/**
 * vips_buf_change:
 * @buf: the buffer
 * @o: the string to search for
 * @n: the string to substitute
 *
 * Swap the rightmost occurence of @o for @n.
 * 
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_change( VipsBuf *buf, const char *old, const char *new )
{
	int olen = strlen( old );
	int nlen = strlen( new );
	int i;

	if( buf->full )
		return( FALSE );
	if( buf->i - olen + nlen > buf->mx - 4 ) {
		buf->full = TRUE;
		return( FALSE );
	}

	/* Find pos of old.
	 */
	for( i = buf->i - olen; i > 0; i-- )
		if( vips_isprefix( old, buf->base + i ) )
			break;
	g_assert( i >= 0 );

	/* Move tail of buffer to make right-size space for new.
	 */
	memmove( buf->base + i + nlen, buf->base + i + olen,
		buf->i - i - olen );

	/* Copy new in.
	 */
	memcpy( buf->base + i, new, nlen );
	buf->i = i + nlen + (buf->i - i - olen);

	return( TRUE );
}

/**
 * vips_buf_removec:
 * @buf: the buffer
 * @ch: the character to remove
 *
 * Remove the last character, if it's @ch.
 * 
 * Returns: %FALSE on failure, %TRUE otherwise.
 */
gboolean
vips_buf_removec( VipsBuf *buf, char ch )
{
	if( buf->full )
		return( FALSE );
	if( buf->i <= 0 ) 
		return( FALSE );
	if( buf->base[buf->i - 1] == ch )
		buf->i -= 1;

	return( TRUE );
}

/**
 * vips_buf_vappendf:
 * @buf: the buffer
 * @fmt: <function>printf()</function>-style format string
 * @ap: arguments to format string
 *
 * Append to @buf, args as <function>vprintf()</function>.
 *
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_vappendf( VipsBuf *buf, const char *fmt, va_list ap )
{
	int avail;
	char *p;

	if( buf->full )
		return( FALSE );

	avail = buf->mx - buf->i - 4;
	p = buf->base + buf->i;
	(void) vips_vsnprintf( p, avail, fmt, ap ); 
	buf->i += strlen( p );

	if( buf->i >= buf->mx - 4 ) {
		buf->full = TRUE;
		strcpy( buf->base + buf->mx - 4, "..." );
		buf->i = buf->mx - 1;
		return( FALSE );
	}

	return( TRUE );
}

/**
 * vips_buf_appendf:
 * @buf: the buffer
 * @fmt: <function>printf()</function>-style format string
 * @...: arguments to format string
 *
 * Format the string and append to @buf.
 * 
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_appendf( VipsBuf *buf, const char *fmt, ... )
{
	va_list ap;
	gboolean result;

        va_start( ap, fmt );
        result = vips_buf_vappendf( buf, fmt, ap );
        va_end( ap );

	return( result );
}

/**
 * vips_buf_appendg:
 * @buf: the buffer
 * @g: value to format and append
 * 
 * Append a double, non-localised. Useful for config files etc.
 * 
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_appendg( VipsBuf *buf, double g )
{
	char text[G_ASCII_DTOSTR_BUF_SIZE];

	g_ascii_dtostr( text, sizeof( text ), g );

	return( vips_buf_appends( buf, text ) );
}

/**
 * vips_buf_appendd:
 * @buf: the buffer
 * @d: value to format and append
 *
 * Append a number. If the number is -ve, add brackets. Needed for
 * building function arguments.
 * 
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_appendd( VipsBuf *buf, int d )
{
	if( d < 0 )
		return( vips_buf_appendf( buf, " (%d)", d ) );
	else
		return( vips_buf_appendf( buf, " %d", d ) );
}

/**
 * vips_buf_appendgv:
 * @buf: the buffer
 * @value: #GValue to format and append
 *
 * Format and append a #GValue as a printable thing. We display text line "3144
 * bytes of binary data" for BLOBs like icc-profile-data.
 *
 * Use vips_image_get_as_string() to make a text representation of a field.
 * That will base64-encode blobs, for example. 
 *
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_appendgv( VipsBuf *buf, GValue *value )
{
	GType type = G_VALUE_TYPE( value ); 
	GType fundamental = g_type_fundamental( type ); 

	gboolean handled;
	gboolean result;

	result = FALSE;
	handled = FALSE;

	switch( fundamental ) {
	case G_TYPE_STRING:
{
		const char *str;

		/* These are GStrings (gchararray). vips refstrings are 
		 * handled by boxed, see below.
		 */
		str = g_value_get_string( value );
		result = vips_buf_appends( buf, str ); 
		handled = TRUE;
}
		break;

	case G_TYPE_OBJECT:
{
		GObject *object;

		object = g_value_get_object( value );
		if( VIPS_IS_OBJECT( object ) ) {
			vips_object_summary( VIPS_OBJECT( object ), buf );
			result = TRUE;
			handled = TRUE;
		}
}
		break;

	case G_TYPE_INT:
		result = vips_buf_appendf( buf, 
			"%d", g_value_get_int( value ) );
		handled = TRUE;
		break;

	case G_TYPE_UINT64:
		result = vips_buf_appendf( buf, 
			"%" G_GINT64_FORMAT, g_value_get_uint64( value ) );
		handled = TRUE;
		break;

	case G_TYPE_DOUBLE:
		result = vips_buf_appendf( buf, 
			"%g", g_value_get_double( value ) );
		handled = TRUE;
		break;

	case G_TYPE_BOOLEAN:
		result = vips_buf_appends( buf, 
			g_value_get_boolean( value ) ? "true" : "false" );
		handled = TRUE;
		break;

	case G_TYPE_ENUM:
		result = vips_buf_appends( buf, 
			vips_enum_nick( type, g_value_get_enum( value ) ) );
		handled = TRUE;
		break;

	case G_TYPE_FLAGS:
{
		GFlagsClass *flags_class = g_type_class_ref( type );

		GFlagsValue *v;
		int flags;

		flags = g_value_get_flags( value );

		while( flags &&
			(v = g_flags_get_first_value( flags_class, flags )) ) {
			result = vips_buf_appendf( buf, "%s ", v->value_nick );
			flags &= ~v->value;
		}

		handled = TRUE;
}
		break;

	case G_TYPE_BOXED:
		if( type == VIPS_TYPE_REF_STRING ) { 
			const char *str;
			size_t str_len;

			/* These should be printable.
			 */
			str = vips_value_get_ref_string( value, &str_len );
			result = vips_buf_appends( buf, str ); 
			handled = TRUE;
		}
		else if( type == VIPS_TYPE_BLOB ) {
			size_t str_len;

			/* Binary data and not printable.
			 */
			(void) vips_value_get_ref_string( value, &str_len );
			result = vips_buf_appendf( buf, 
				_( "%zd bytes of binary data" ), str_len ); 
			handled = TRUE;
		}
		else if( type == VIPS_TYPE_ARRAY_DOUBLE ) {
			double *arr;
			int n;
			int i;

			arr = vips_value_get_array_double( value, &n );
			for( i = 0; i < n; i++ ) 
				result = vips_buf_appendf( buf, "%g ", arr[i] ); 
			handled = TRUE;
		}
		else if( type == VIPS_TYPE_ARRAY_INT ) {
			int *arr;
			int n;
			int i;

			arr = vips_value_get_array_int( value, &n );
			for( i = 0; i < n; i++ ) 
				result = vips_buf_appendf( buf, "%d ", arr[i] ); 
			handled = TRUE;
		}
		else if( type == VIPS_TYPE_ARRAY_IMAGE ) {
			VipsImage **arr;
			int n;
			int i;

			arr = vips_value_get_array_image( value, &n );
			for( i = 0; i < n; i++ ) {
				vips_object_summary( VIPS_OBJECT( arr[i] ), 
					buf );
				result = vips_buf_appends( buf, " " ); 
			}
			handled = TRUE;
		}
		break;

	default:
		break;
	}

	if( !handled ) { 
		char *str_value;

		str_value = g_strdup_value_contents( value );
		result = vips_buf_appends( buf, str_value );
		g_free( str_value );
	}

	return( result );
}

/**
 * vips_buf_append_size:
 * @buf: the buffer
 * @n: the number of bytes
 *
 * Turn a number of bytes into a sensible string ... eg "12", "12KB", "12MB",
 * "12GB" etc.
 * 
 * Returns: %FALSE on overflow, %TRUE otherwise.
 */
gboolean
vips_buf_append_size( VipsBuf *buf, size_t n )
{
	const static char *names[] = { 
		/* File length unit.
		 */
		N_( "bytes" ), 

		/* Kilobyte unit.
		 */
		N_( "KB" ), 

		/* Megabyte unit.
		 */
		N_( "MB" ), 

		/* Gigabyte unit.
		 */
		N_( "GB" ), 

		/* Terabyte unit.
		 */
		N_( "TB" ) 
	};

	double sz = n;
	int i;

	/* -1, since we want to stop at TB, not run off the end.
	 */
	for( i = 0; sz > 1024 && i < VIPS_NUMBER( names ) - 1; sz /= 1024, i++ )
		;

	if( i == 0 )
		/* No decimal places for bytes.
		 */
		return( vips_buf_appendf( buf, "%g %s", sz, _( names[i] ) ) );
	else 
		return( vips_buf_appendf( buf, "%.2f %s", sz, _( names[i] ) ) );
}

/**
 * vips_buf_all:
 * @buf: the buffer
 *
 * Return the contents of the buffer as a C string. 
 * 
 * Returns: the %NULL-terminated contents of the buffer. This is a pointer to
 * the memory managed by the buffer and must not be freed. 
 */
const char *
vips_buf_all( VipsBuf *buf )
{
	buf->base[buf->i] = '\0';

	return( buf->base );
}

/**
 * vips_buf_firstline:
 * @buf: the buffer
 *
 * Trim to just the first line (excluding "\n").
 * 
 * Returns: the %NULL-terminated contents of the buffer. This is a pointer to
 * the memory managed by the buffer and must not be freed. 
 */
const char *
vips_buf_firstline( VipsBuf *buf )
{
	char *p;

	if( (p = strchr( vips_buf_all( buf ), '\n' )) )
		*p = '\0';

	return( vips_buf_all( buf ) );
}

/**
 * vips_buf_is_empty:
 * @buf: the buffer
 *
 * Returns: %TRUE if the buffer is empty.
 */
gboolean
vips_buf_is_empty( VipsBuf *buf )
{
	return( buf->i == 0 );
}

/**
 * vips_buf_is_full:
 * @buf: the buffer
 *
 * Returns: %TRUE if the buffer is full.
 */
gboolean
vips_buf_is_full( VipsBuf *buf )
{
	return( buf->full );
}

/**
 * vips_buf_len:
 * @buf: the buffer
 *
 * Returns: the number of characters currently in the buffer.
 */
int
vips_buf_len( VipsBuf *buf )
{
	return( buf->i );
}

