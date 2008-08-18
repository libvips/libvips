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
im_buf_rewind( im_buf_t *buf )
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
im_buf_init( im_buf_t *buf )
{
	buf->base = NULL;
	buf->mx = 0;
	buf->dynamic = FALSE;
	im_buf_rewind( buf );
}

/* Reset to power on state ... only needed for dynamic bufs.
 */
void
im_buf_destroy( im_buf_t *buf )
{
	if( buf->dynamic ) {
		if( buf->base ) {
			im_free( buf->base );
			buf->base = NULL;
		}
	}

	im_buf_init( buf );
}

/* Set to a static string.
 */
void
im_buf_set_static( im_buf_t *buf, char *base, int mx )
{
	assert( mx >= 4 );

	im_buf_destroy( buf );

	buf->base = base;
	buf->mx = mx;
	buf->dynamic = FALSE;
	im_buf_rewind( buf );
}

void
im_buf_init_static( im_buf_t *buf, char *base, int mx )
{
	im_buf_init( buf );
	im_buf_set_static( buf, base, mx );
}

/* Set to a dynamic string.
 */
void
im_buf_set_dynamic( im_buf_t *buf, int mx )
{
	assert( mx >= 4 );

	if( buf->mx == mx && buf->dynamic ) 
		/* No change?
		 */
		im_buf_rewind( buf );
	else {
		im_buf_destroy( buf );

		if( !(buf->base = IM_ARRAY( NULL, mx, char )) )
			/* No error return, so just block writes.
			 */
			buf->full = TRUE;
		else {
			buf->mx = mx;
			buf->dynamic = TRUE;
			im_buf_rewind( buf );
		}
	}
}

void
im_buf_init_dynamic( im_buf_t *buf, int mx )
{
	im_buf_init( buf );
	im_buf_set_dynamic( buf, mx );
}

/* Append at most sz chars from string to buf. sz < 0 means unlimited.
 * FALSE on overflow.
 */
gboolean
im_buf_appendns( im_buf_t *buf, const char *str, int sz )
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
im_buf_appends( im_buf_t *buf, const char *str )
{
	return( im_buf_appendns( buf, str, -1 ) );
}

/* Append a character to a buf. Error on overflow.
 */
gboolean
im_buf_appendc( im_buf_t *buf, char ch )
{
	char tiny[2];

	tiny[0] = ch;
	tiny[1] = '\0';

	return( im_buf_appendns( buf, tiny, 1 ) );
}

/* Append a double, non-localised. Useful for config files etc.
 */
gboolean
im_buf_appendg( im_buf_t *buf, double g )
{
	char text[G_ASCII_DTOSTR_BUF_SIZE];

	g_ascii_dtostr( text, sizeof( text ), g );

	return( im_buf_appends( buf, text ) );
}


/* Swap the rightmost occurence of old for new.
 */
gboolean
im_buf_change( im_buf_t *buf, const char *old, const char *new )
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
	assert( i >= 0 );

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

/* Remove the last character.
 */
gboolean
im_buf_removec( im_buf_t *buf, char ch )
{
	if( buf->full )
		return( FALSE );

	if( buf->i <= 0 ) 
		return( FALSE );
	buf->i -= 1;
	assert( buf->base[buf->i] == ch );

	return( TRUE );
}

/* Append to a buf, args as printf. FALSE on overflow.
 */
gboolean
im_buf_appendf( im_buf_t *buf, const char *fmt, ... )
{
	va_list ap;
	char str[MAX_STRSIZE];

        va_start( ap, fmt );
        (void) im_vsnprintf( str, MAX_STRSIZE, fmt, ap );
        va_end( ap );

	return( im_buf_appends( buf, str ) );
}

/* Append to a buf, args as vprintf. Error on overflow.
 */
gboolean
im_buf_vappendf( im_buf_t *buf, const char *fmt, va_list ap )
{
	char str[MAX_STRSIZE];

        (void) im_vsnprintf( str, MAX_STRSIZE, fmt, ap );

	return( im_buf_appends( buf, str ) );
}

/* Read all text from buffer.
 */
const char *
im_buf_all( im_buf_t *buf )
{
	buf->base[buf->i] = '\0';

	return( buf->base );
}

gboolean
im_buf_isempty( im_buf_t *buf )
{
	return( buf->i == 0 );
}

gboolean
im_buf_isfull( im_buf_t *buf )
{
	return( buf->full );
}

/* Buffer length ... still need to do im_buf_all().
 */
int
im_buf_len( im_buf_t *buf )
{
	return( buf->i );
}
