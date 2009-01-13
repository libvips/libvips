/* string buffers
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <vips/vips.h>
#include <vips/buf.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Largest string we can append in one operation.
 */
#define MAX_STRSIZE (16000)

void
vips_buf_rewind( VipsBuf *buf )
{
	buf->i = 0;
	buf->lasti = 0;
	buf->full = FALSE;

	if( buf->base )
		buf->base[0] = '\0';
}

/* Power on init.
 */
void
vips_buf_init( VipsBuf *buf )
{
	buf->base = NULL;
	buf->mx = 0;
	buf->dynamic = FALSE;
	vips_buf_rewind( buf );
}

/* Reset to power on state ... only needed for dynamic bufs.
 */
void
vips_buf_destroy( VipsBuf *buf )
{
	if( buf->dynamic ) {
		IM_FREE( buf->base );
	}

	vips_buf_init( buf );
}

/* Set to a static string.
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

void
vips_buf_init_static( VipsBuf *buf, char *base, int mx )
{
	vips_buf_init( buf );
	vips_buf_set_static( buf, base, mx );
}

/* Set to a dynamic string.
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

		if( !(buf->base = IM_ARRAY( NULL, mx, char )) )
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

void
vips_buf_init_dynamic( VipsBuf *buf, int mx )
{
	vips_buf_init( buf );
	vips_buf_set_dynamic( buf, mx );
}

/* Append at most sz chars from string to buf. sz < 0 means unlimited.
 * Error on overflow.
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
		n = IM_MIN( sz, len );
	else
		n = len;

	/* Space available.
	 */
	avail = buf->mx - buf->i - 4;

	/* Amount we actually copy.
	 */
	cpy = IM_MIN( n, avail );

	strncpy( buf->base + buf->i, str, cpy );
	buf->i += cpy;

	if( buf->i >= buf->mx - 4 ) {
		buf->full = TRUE;
		strcpy( buf->base + buf->mx - 4, "..." );
		buf->i = buf->mx - 1;
		return( FALSE );
	}

	return( TRUE );
}

/* Append a string to a buf. Error on overflow.
 */
gboolean
vips_buf_appends( VipsBuf *buf, const char *str )
{
	return( vips_buf_appendns( buf, str, -1 ) );
}

/* Append a character to a buf. Error on overflow.
 */
gboolean
vips_buf_appendc( VipsBuf *buf, char ch )
{
	char tiny[2];

	tiny[0] = ch;
	tiny[1] = '\0';

	return( vips_buf_appendns( buf, tiny, 1 ) );
}

/* Swap the rightmost occurence of old for new.
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
		if( im_isprefix( old, buf->base + i ) )
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

/* Remove the last character, if it's ch.
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

/* Append to a buf, args as printf. Error on overflow.
 */
gboolean
vips_buf_appendf( VipsBuf *buf, const char *fmt, ... )
{
	char str[MAX_STRSIZE];
	va_list ap;

        va_start( ap, fmt );
        (void) im_vsnprintf( str, MAX_STRSIZE, fmt, ap );
        va_end( ap );

	return( vips_buf_appends( buf, str ) );
}

/* Append to a buf, args as vprintf. Error on overflow.
 */
gboolean
vips_buf_vappendf( VipsBuf *buf, const char *fmt, va_list ap )
{
	char str[MAX_STRSIZE];

        (void) im_vsnprintf( str, MAX_STRSIZE, fmt, ap );

	return( vips_buf_appends( buf, str ) );
}

/* Append a double, non-localised. Useful for config files etc.
 */
gboolean
vips_buf_appendg( VipsBuf *buf, double g )
{
	char text[G_ASCII_DTOSTR_BUF_SIZE];

	g_ascii_dtostr( text, sizeof( text ), g );

	return( vips_buf_appends( buf, text ) );
}

/* Append a number ... if the number is -ve, add brackets. Needed for
 * building function arguments.
 */
gboolean
vips_buf_appendd( VipsBuf *buf, int d )
{
	if( d < 0 )
		return( vips_buf_appendf( buf, " (%d)", d ) );
	else
		return( vips_buf_appendf( buf, " %d", d ) );
}

void
vips_buf_appendgv( VipsBuf *buf, GValue *value )
{
	char *str_value;

	str_value = g_strdup_value_contents( value );
	vips_buf_appends( buf, str_value );
	g_free( str_value );
}

/* Read all text from buffer.
 */
const char *
vips_buf_all( VipsBuf *buf )
{
	buf->base[buf->i] = '\0';

	return( buf->base );
}

/* Trim to just the first line (excluding "\n").
 */
const char *
vips_buf_firstline( VipsBuf *buf )
{
	char *p;

	if( (p = strchr( vips_buf_all( buf ), '\n' )) )
		*p = '\0';

	return( vips_buf_all( buf ) );
}

/* Test for buffer empty.
 */
gboolean
vips_buf_is_empty( VipsBuf *buf )
{
	return( buf->i == 0 );
}

/* Test for buffer full.
 */
gboolean
vips_buf_is_full( VipsBuf *buf )
{
	return( buf->full );
}

/* VipsBuffer length ... still need to do vips_buf_all().
 */
int
vips_buf_len( VipsBuf *buf )
{
	return( buf->i );
}

