/* @(#) error handling
 * @(#) 
 * @(#)  Usage:
 * @(#)  void im_errormsg(variable_list)
 * @(#)  (variable_list) is (format, arg1, arg2, ...)
 * @(#) format, arg1, arg2, etc are the same as in fprintf
 * @(#) 
 * Copyright: N. Dessipris 
 * Written on: 18/03/1991
 * Updated on: 9/7/92 KM
 * 20/12/2003 JC
 *	- i18n added, domain now separate arg
 * 14/2/07
 * 	- lock around error buffer changes
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/vbuf.h>
#include <vips/thread.h>

#ifdef OS_WIN32
#include <windows.h>
#include <lmerr.h>
#endif /*OS_WIN32*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Make global array to keep the error message buffer.
 */
#define IM_MAX_ERROR (10240)
static char im_error_text[IM_MAX_ERROR] = "";
static VBuf im_error_buf = 
	IM_BUF_STATIC( im_error_text, IM_MAX_ERROR );

#define IM_DIAGNOSTICS "IM_DIAGNOSTICS"
#define IM_WARNING "IM_WARNING"

const char *
im_error_buffer( void )
{
	const char *msg;

	g_mutex_lock( im__global_lock );
	msg = im_buf_all( &im_error_buf );
	g_mutex_unlock( im__global_lock );

	return( msg );
}

void 
im_verror( const char *domain, const char *fmt, va_list ap )
{
	g_mutex_lock( im__global_lock );
	im_buf_appendf( &im_error_buf, "%s: ", domain );
	im_buf_vappendf( &im_error_buf, fmt, ap );
	im_buf_appends( &im_error_buf, "\n" );
	g_mutex_unlock( im__global_lock );
}

void 
im_error( const char *domain, const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	im_verror( domain, fmt, ap );
	va_end( ap );
}

void
im_verror_system( int err, const char *domain, const char *fmt, va_list ap )
{
	im_verror( domain, fmt, ap );

#ifdef OS_WIN32
{
	char *buf;

	if( FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		err,
		MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), 
		(LPSTR) &buf, 0, NULL ) ) {
		im_error( _( "windows error" ), "%s", buf );
		LocalFree( buf );
	}
}
#else /*OS_WIN32*/
{
	char *buf;

	buf = g_locale_to_utf8( strerror( err ), -1, NULL, NULL, NULL );
	im_error( _( "unix error" ), "%s", buf );
	g_free( buf );
}
#endif /*OS_WIN32*/
}

void
im_error_system( int err, const char *domain, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	im_verror_system( err, domain, fmt, ap );
	va_end( ap );
}

void 
im_error_clear( void )
{
	g_mutex_lock( im__global_lock );
	im_buf_rewind( &im_error_buf );
	g_mutex_unlock( im__global_lock );
}

void 
im_vdiag( const char *domain, const char *fmt, va_list ap )
{
	if( !g_getenv( IM_DIAGNOSTICS ) ) {
		(void) fprintf( stderr, _( "%s: " ), _( "vips diagnostic" ) );
		(void) fprintf( stderr, _( "%s: " ), domain );
		(void) vfprintf( stderr, fmt, ap );
		(void) fprintf( stderr, "\n" );
	}
}

void 
im_diag( const char *domain, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	im_vdiag( domain, fmt, ap );
	va_end( ap );
}

void 
im_vwarn( const char *domain, const char *fmt, va_list ap )
{	
	if( !g_getenv( IM_WARNING ) ) {
		(void) fprintf( stderr, _( "%s: " ), _( "vips warning" ) );
		(void) fprintf( stderr, _( "%s: " ), domain );
		(void) vfprintf( stderr, fmt, ap );
		(void) fprintf( stderr, "\n" );
	}
}

void 
im_warn( const char *domain, const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	im_vwarn( domain, fmt, ap );
	va_end( ap );
}

/* Compatibility with pre-7.10 ... can't portably do these as macros sadly.
 */

void 
im_errormsg( const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	im_verror( "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_verrormsg( const char *fmt, va_list ap )
{	
	im_verror( "untranslated", fmt, ap );
}

void
im_errormsg_system( int err,  const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	im_verror_system( err, "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_diagnostics( const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	im_vdiag( "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_warning( const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	im_vwarn( "untranslated", fmt, ap );
	va_end( ap );
}
