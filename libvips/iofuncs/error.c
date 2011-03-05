/* error.c --- error message handling 
 *
 * Copyright: N. Dessipris 
 * Written on: 18/03/1991
 * Updated on: 9/7/92 KM
 * 20/12/2003 JC
 *	- i18n added, domain now separate arg
 * 14/2/07
 * 	- lock around error buffer changes
 * 20/2/08
 * 	- lock around warnings and diagnostics too, why not
 * 2/10/09
 * 	- error_exit() moved here
 * 	- gtkdoc comments
 * 24/6/10
 * 	- fmt to error_exit() may be NULL
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
#include <vips/buf.h>
#include <vips/thread.h>

#ifdef OS_WIN32
#include <windows.h>
#include <lmerr.h>
#endif /*OS_WIN32*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: error
 * @short_description: error messages and error handling
 * @stability: Stable
 * @include: vips/vips.h
 *
 * VIPS maintains an error buffer (a log of localised text messages), 
 * a set of functions
 * for adding messages, and a way to access and clear the buffer.
 *
 * The error buffer is global, that is, it is shared between all threads. You
 * can add to the buffer from any thread (there is a lock to prevent
 * corruption), but it's sensible to only read and clear the buffer from the
 * main thread of execution.
 *
 * The general principle is: if you detect an error, log a message for the
 * user. If a function you call detects an error, just propogate it and don't
 * add another message.
 *
 * |[
 * IMAGE *im;
 *
 * if( !(im = im_open( filename, "r" )) )
 *   // im_open will set a mmessage, we don't need to
 *   return( -1 );
 *
 * if( im->Xsize < 100 ) {
 *   // we have detected an error, we must set a message
 *   vips_error( "myprogram", "%s", _( "XSize too small" ) );
 *   return( -1 );
 * }
 * ]|
 *
 * The domain argument most of these functions take is not localised and is
 * supposed to indicate the component which failed.
 */

/* Make global array to keep the error message buffer.
 */
#define IM_MAX_ERROR (10240)
static char vips_error_text[IM_MAX_ERROR] = "";
static VipsBuf vips_error_buf = VIPS_BUF_STATIC( vips_error_text );

#define IM_DIAGNOSTICS "IM_DIAGNOSTICS"
#define IM_WARNING "IM_WARNING"

/**
 * vips_error_buffer: 
 *
 * Get a pointer to the start of the error buffer as a C string.
 * The string is owned by the error system and must not be freed.
 *
 * See also: vips_error_clear().
 *
 * Returns: the error buffer as a C string which must not be freed
 */
const char *
vips_error_buffer( void )
{
	const char *msg;

	g_mutex_lock( vips__global_lock );
	msg = vips_buf_all( &vips_error_buf );
	g_mutex_unlock( vips__global_lock );

	return( msg );
}

/**
 * vips_verror: 
 * @domain: the source of the error
 * @fmt: printf()-style format string for the error
 * @ap: arguments to the format string
 *
 * Append a message to the error buffer.
 *
 * See also: vips_error().
 */
void 
vips_verror( const char *domain, const char *fmt, va_list ap )
{
	g_mutex_lock( vips__global_lock );
	vips_buf_appendf( &vips_error_buf, "%s: ", domain );
	vips_buf_vappendf( &vips_error_buf, fmt, ap );
	vips_buf_appends( &vips_error_buf, "\n" );
	g_mutex_unlock( vips__global_lock );
}

/**
 * vips_error: 
 * @domain: the source of the error
 * @fmt: printf()-style format string for the error
 * @Varargs: arguments to the format string
 *
 * Format the string in the style of printf() and append to the error buffer.
 *
 * See also: vips_error_system(), vips_verror().
 */
void 
vips_error( const char *domain, const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	vips_verror( domain, fmt, ap );
	va_end( ap );
}

/**
 * vips_verror_system: 
 * @err: the system error code
 * @domain: the source of the error
 * @fmt: printf()-style format string for the error
 * @ap: arguments to the format string
 *
 * Format the string in the style of printf() and append to the error buffer.
 * Then create and append a localised message based on the system error code,
 * usually the value of errno.
 *
 * See also: vips_error_system().
 */
void
vips_verror_system( int err, const char *domain, const char *fmt, va_list ap )
{
	vips_verror( domain, fmt, ap );

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
	vips_error( _( "unix error" ), "%s", buf );
	g_free( buf );
}
#endif /*OS_WIN32*/
}

/**
 * vips_error_system: 
 * @err: the system error code
 * @domain: the source of the error
 * @fmt: printf()-style format string for the error
 * @Varargs: arguments to the format string
 *
 * Format the string in the style of printf() and append to the error buffer.
 * Then create and append a localised message based on the system error code,
 * usually the value of errno.
 *
 * See also: vips_verror_system().
 */
void
vips_error_system( int err, const char *domain, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	vips_verror_system( err, domain, fmt, ap );
	va_end( ap );
}

/**
 * vips_error_clear: 
 *
 * Clear and reset the error buffer. This is typically called after presentng
 * an error to the user.
 *
 * See also: vips_error_buffer().
 */
void 
vips_error_clear( void )
{
	g_mutex_lock( vips__global_lock );
	vips_buf_rewind( &vips_error_buf );
	g_mutex_unlock( vips__global_lock );
}

/**
 * vips_vdiag: 
 * @domain: the source of the diagnostic message
 * @fmt: printf()-style format string for the message
 * @ap: arguments to the format string
 *
 * Sends a formatted diagnostic message to stderr. If you define the
 * environment variable IM_DIAGNOSTICS, these message are surpressed.
 *
 * Diagnostic messages are used to report details about the operation of
 * functions.
 *
 * See also: vips_diag(), vips_warn().
 */
void 
vips_vdiag( const char *domain, const char *fmt, va_list ap )
{
	if( !g_getenv( IM_DIAGNOSTICS ) ) {
		g_mutex_lock( vips__global_lock );
		(void) fprintf( stderr, _( "%s: " ), _( "vips diagnostic" ) );
		(void) fprintf( stderr, _( "%s: " ), domain );
		(void) vfprintf( stderr, fmt, ap );
		(void) fprintf( stderr, "\n" );
		g_mutex_unlock( vips__global_lock );
	}
}

/**
 * vips_diag: 
 * @domain: the source of the diagnostic message
 * @fmt: printf()-style format string for the message
 * @Varargs: arguments to the format string
 *
 * Sends a formatted diagnostic message to stderr. If you define the
 * environment variable IM_DIAGNOSTICS, these message are surpressed.
 *
 * Diagnostic messages are used to report details about the operation of
 * functions.
 *
 * See also: vips_vdiag(), vips_warn().
 */
void 
vips_diag( const char *domain, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	vips_vdiag( domain, fmt, ap );
	va_end( ap );
}

/**
 * vips_vwarn: 
 * @domain: the source of the warning message
 * @fmt: printf()-style format string for the message
 * @ap: arguments to the format string
 *
 * Sends a formatted warning message to stderr. If you define the
 * environment variable IM_WARNING, these message are surpressed.
 *
 * Warning messages are used to report things like overflow counts.
 *
 * See also: vips_diag(), vips_warn().
 */
void 
vips_vwarn( const char *domain, const char *fmt, va_list ap )
{	
	if( !g_getenv( IM_WARNING ) ) {
		g_mutex_lock( vips__global_lock );
		(void) fprintf( stderr, _( "%s: " ), _( "vips warning" ) );
		(void) fprintf( stderr, _( "%s: " ), domain );
		(void) vfprintf( stderr, fmt, ap );
		(void) fprintf( stderr, "\n" );
		g_mutex_unlock( vips__global_lock );
	}
}

/**
 * vips_warn: 
 * @domain: the source of the warning message
 * @fmt: printf()-style format string for the message
 * @Varargs: arguments to the format string
 *
 * Sends a formatted warning message to stderr. If you define the
 * environment variable IM_WARNING, these message are surpressed.
 *
 * Warning messages are used to report things like overflow counts.
 *
 * See also: vips_diag(), vips_vwarn().
 */
void 
vips_warn( const char *domain, const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	vips_vwarn( domain, fmt, ap );
	va_end( ap );
}

/**
 * vips_error_exit: 
 * @fmt: printf()-style format string for the message
 * @Varargs: arguments to the format string
 *
 * Sends a formatted error message to stderr, then sends the contents of the
 * error buffer, if any, then terminates the program with an error code.
 *
 * @fmt may be %NULL, in which case only the error buffer is printed before
 * exiting.
 *
 * See also: vips_error().
 */
void 
vips_error_exit( const char *fmt, ... )
{	
	if( fmt ) {
		va_list ap;

		fprintf( stderr, "%s: ", g_get_prgname() );

		va_start( ap, fmt );
		(void) vfprintf( stderr, fmt, ap );
		va_end( ap );

		fprintf( stderr, "\n" );
	}

	fprintf( stderr, "%s", vips_error_buffer() );

	exit( 1 );
}
