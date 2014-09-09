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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/buf.h>
#include <vips/thread.h>
#include <vips/debug.h>

#ifdef OS_WIN32
#include <windows.h>
#include <lmerr.h>
#endif /*OS_WIN32*/

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
 * if( !(im = vips_image_new_from_file( filename, NULL )) )
 *   // vips_image_new_from_file() will set a message, we don't need to
 *   return( -1 );
 *
 * if( vips_image_get_width( im ) < 100 ) {
 *   // we have detected an error, we must set a message
 *   vips_error( "myprogram", "%s", _( "width too small" ) );
 *   return( -1 );
 * }
 * ]|
 *
 * The domain argument most of these functions take is not localised and is
 * supposed to indicate the component which failed.
 */

/* Show info messages. Handy for debugging. 
 */
int vips__info = 0;

/* Make global array to keep the error message buffer.
 */
#define VIPS_MAX_ERROR (10240)
static char vips_error_text[VIPS_MAX_ERROR] = "";
static VipsBuf vips_error_buf = VIPS_BUF_STATIC( vips_error_text );
static int vips_error_freeze_count = 0;

/**
 * vips_error_freeze:
 *
 * Stop errors being logged. Use vips_error_thaw() to unfreeze. You can
 * nest freeze/thaw pairs.
 */
void
vips_error_freeze( void )
{
	g_mutex_lock( vips__global_lock );
	g_assert( vips_error_freeze_count >= 0 );
	vips_error_freeze_count += 1;
	g_mutex_unlock( vips__global_lock );
}

/**
 * vips_error_thaw:
 *
 * Reenable error logging. 
 */
void
vips_error_thaw( void )
{
	g_mutex_lock( vips__global_lock );
	vips_error_freeze_count -= 1;
	g_assert( vips_error_freeze_count >= 0 );
	g_mutex_unlock( vips__global_lock );
}

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

/* Some systems do not have va_copy() ... this might work (it does on MSVC),
 * apparently.
 *
 * FIXME ... this should be in configure.in
 */
#ifndef va_copy
#define va_copy(d,s) ((d) = (s))
#endif

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
#ifdef VIPS_DEBUG
{
	char txt[256];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	va_list ap2;

	vips_buf_appendf( &buf, "%s: ", domain );
	va_copy( ap2, ap );
	vips_buf_vappendf( &buf, fmt, ap2 );
	vips_buf_appends( &buf, "\n" );
	VIPS_DEBUG_MSG( "vips_verror: %s", vips_buf_all( &buf ) );
}
#endif /*VIPS_DEBUG*/

	g_mutex_lock( vips__global_lock );
	g_assert( vips_error_freeze_count >= 0 );
	if( !vips_error_freeze_count ) {
		vips_buf_appendf( &vips_error_buf, "%s: ", domain );
		vips_buf_vappendf( &vips_error_buf, fmt, ap );
		vips_buf_appends( &vips_error_buf, "\n" );
	}
	g_mutex_unlock( vips__global_lock );

	if( vips__fatal )
		vips_error_exit( "vips__fatal" );
}

/**
 * vips_error: 
 * @domain: the source of the error
 * @fmt: printf()-style format string for the error
 * @...: arguments to the format string
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
		vips_error( _( "windows error" ), "%s", buf );
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
 * @...: arguments to the format string
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
 * vips_error_g:
 * @error: glib error pointer
 *
 * This function sets the glib error pointer from the vips error buffer and
 * clears it. It's handy for returning errors to glib functions from vips.
 *
 * See vips_g_error() for the inverse operation.
 *
 * See also: g_set_error(), vips_g_error().
 */
void
vips_error_g( GError **error )
{
	static GQuark vips_domain = 0;

	if( !vips_domain ) 
		vips_domain = g_quark_from_string( "libvips" );

	/* glib does not expect a trailing '\n' and vips always has one.
	 */
	g_mutex_lock( vips__global_lock );
	vips_buf_removec( &vips_error_buf, '\n' );
	g_mutex_unlock( vips__global_lock );

	g_set_error( error, vips_domain, -1, "%s", vips_error_buffer() );
	vips_error_clear();
}


/**
 * vips_g_error:
 * @error: glib error pointer
 *
 * This function adds the %GError to the vips error buffer and clears it. It's
 * the opposite of vips_error_g().
 *
 * See also: vips_error_g(). 
 */
void
vips_g_error( GError **error )
{
	if( error &&
		*error ) {
		vips_error( "glib", "%s\n", (*error)->message ); 
		g_error_free( *error );
		*error = NULL;
	}
}

/**
 * vips_error_clear: 
 *
 * Clear and reset the error buffer. This is typically called after presenting
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
 * vips_vinfo: 
 * @domain: the source of the message
 * @fmt: printf()-style format string for the message
 * @ap: arguments to the format string
 *
 * Sends a formatted informational message to stderr if the --vips-info flag
 * has been given to the program or the environment variable IM_INFO has been
 * defined. 
 *
 * Informational messages are used to report details about the operation of
 * functions.
 *
 * See also: vips_info(), vips_warn().
 */
void 
vips_vinfo( const char *domain, const char *fmt, va_list ap )
{
	if( vips__info ) { 
		g_mutex_lock( vips__global_lock );
		(void) fprintf( stderr, _( "%s: " ), _( "info" ) );
		if( domain )
			(void) fprintf( stderr, _( "%s: " ), domain );
		(void) vfprintf( stderr, fmt, ap );
		(void) fprintf( stderr, "\n" );
		g_mutex_unlock( vips__global_lock );
	}
}

/**
 * vips_info: 
 * @domain: the source of the diagnostic message
 * @fmt: printf()-style format string for the message
 * @...: arguments to the format string
 *
 * Sends a formatted informational message to stderr if the --vips-info flag
 * has been given to the program or the environment variable IM_INFO has been
 * defined. 
 *
 * Informational messages are used to report details about the operation of
 * functions.
 *
 * See also: vips_vdiag(), vips_warn().
 */
void 
vips_info( const char *domain, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	vips_vinfo( domain, fmt, ap );
	va_end( ap );
}

/**
 * vips_vwarn: 
 * @domain: the source of the warning message
 * @fmt: printf()-style format string for the message
 * @ap: arguments to the format string
 *
 * Sends a formatted warning message to stderr. If you define the
 * environment variable VIPS_WARNING, these message are surpressed.
 *
 * Warning messages are used to report things like overflow counts.
 *
 * See also: vips_info(), vips_warn().
 */
void 
vips_vwarn( const char *domain, const char *fmt, va_list ap )
{	
	if( !g_getenv( "IM_WARNING" ) &&
		!g_getenv( "VIPS_WARNING" ) ) {
		g_mutex_lock( vips__global_lock );
		(void) fprintf( stderr, _( "%s: " ), _( "vips warning" ) );
		if( domain )
			(void) fprintf( stderr, _( "%s: " ), domain );
		(void) vfprintf( stderr, fmt, ap );
		(void) fprintf( stderr, "\n" );
		g_mutex_unlock( vips__global_lock );
	}

	if( vips__fatal )
		vips_error_exit( "vips__fatal" );
}

/**
 * vips_warn: 
 * @domain: the source of the warning message
 * @fmt: printf()-style format string for the message
 * @...: arguments to the format string
 *
 * Sends a formatted warning message to stderr. If you define the
 * environment variable IM_WARNING, these message are surpressed.
 *
 * Warning messages are used to report things like overflow counts.
 *
 * See also: vips_info(), vips_vwarn().
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
 * @...: arguments to the format string
 *
 * Sends a formatted error message to stderr, then sends the contents of the
 * error buffer, if any, then shuts down vips and terminates the program with 
 * an error code.
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

	vips_shutdown();

	if( vips__fatal )
		abort();
	else
		exit( 1 );
}

/**
 * vips_check_uncoded:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is not coded. 
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
vips_check_uncoded( const char *domain, VipsImage *im )
{
	if( im->Coding != VIPS_CODING_NONE ) {
		vips_error( domain, "%s", _( "image must be uncoded" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_coding_noneorlabq:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is uncoded or LABQ coded.
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
vips_check_coding_noneorlabq( const char *domain, VipsImage *im )
{
	/* These all have codings that extract/ifthenelse/etc can ignore.
	 */
	if( im->Coding != VIPS_CODING_NONE && 
		im->Coding != VIPS_CODING_LABQ ) {
		vips_error( domain, 
			"%s", _( "image coding must be 'none' or 'labq'" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_coding_known:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is uncoded, LABQ coded or RAD coded. 
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
vips_check_coding_known( const char *domain, VipsImage *im )
{
	/* These all have codings that extract/ifthenelse/etc can ignore.
	 */
	if( im->Coding != VIPS_CODING_NONE && 
		im->Coding != VIPS_CODING_LABQ &&
		im->Coding != VIPS_CODING_RAD ) {
		vips_error( domain, "%s", _( "unknown image coding" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_coding:
 * @domain: the originating domain for the error message
 * @im: image to check
 * @coding: required coding
 *
 * Check that the image has the required @coding.
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
vips_check_coding( const char *domain, VipsImage *im, VipsCoding coding )
{
	if( im->Coding != coding ) {
		vips_error( domain, _( "coding '%s' only" ), 
			vips_enum_nick( VIPS_TYPE_CODING, coding ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_mono:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image has exactly one band.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_mono( const char *domain, VipsImage *im )
{
	if( im->Bands != 1 ) {
		vips_error( domain, "%s", _( "image must one band" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_bands:
 * @domain: the originating domain for the error message
 * @im: image to check
 * @bands: must have this many bands
 *
 * Check that the image has @bands bands.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_bands( const char *domain, VipsImage *im, int bands )
{
	if( im->Bands != bands ) {
		vips_error( domain, _( "image must have %d bands" ), bands );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_bands_1or3:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image has either one or three bands.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_bands_1or3( const char *domain, VipsImage *im )
{
	if( im->Bands != 1 && im->Bands != 3 ) {
		vips_error( domain, "%s", 
			_( "image must have one or three bands" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_bands_atleast:
 * @domain: the originating domain for the error message
 * @im: image to check
 * @bands: at least this many bands
 *
 * Check that the image has at least @bands bands. 
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_bands_atleast( const char *domain, VipsImage *im, int bands )
{
	if( im->Bands < bands ) {
		vips_error( domain, 
			_( "image must have at least %d bands" ), bands );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_bands_1orn:
 * @domain: the originating domain for the error message
 * @im1: first image to check
 * @im2: second image to check
 *
 * Check that the images have the same number of bands, or that one of the
 * images has just 1 band.
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
vips_check_bands_1orn( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->Bands != im2->Bands &&
		(im1->Bands != 1 && im2->Bands != 1) ) {
		vips_error( domain, "%s", 
			_( "images must have the same number of bands, "
			"or one must be single-band" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_bands_1orn_unary:
 * @domain: the originating domain for the error message
 * @im: image to check
 * @n: number of bands, or 1
 *
 * Check that an image has 1 or @n bands. Handy for unary operations, cf.
 * vips_check_bands_1orn().
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_check_bands_1orn().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
vips_check_bands_1orn_unary( const char *domain, VipsImage *im, int n )
{
	if( im->Bands != 1 && im->Bands != n ) { 
		vips_error( domain, _( "image must have 1 or %d bands" ), n );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_noncomplex:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is not complex.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_noncomplex( const char *domain, VipsImage *im )
{
	if( vips_band_format_iscomplex( im->BandFmt ) ) {
		vips_error( domain, "%s", _( "image must be non-complex" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_complex:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is complex.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_complex( const char *domain, VipsImage *im )
{
	if( !vips_band_format_iscomplex( im->BandFmt ) ) {
		vips_error( domain, "%s", _( "image must be complex" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_format:
 * @domain: the originating domain for the error message
 * @im: image to check
 * @fmt: format to test for
 *
 * Check that the image has the specified format.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_format( const char *domain, VipsImage *im, VipsBandFormat fmt )
{
	if( im->BandFmt != fmt ) {
		vips_error( domain, 
			_( "image must be %s" ), 
			vips_enum_string( VIPS_TYPE_BAND_FORMAT, fmt ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_int:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is in one of the integer formats.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_int( const char *domain, VipsImage *im )
{
	if( !vips_band_format_isint( im->BandFmt ) ) {
		vips_error( domain, "%s", _( "image must be integer" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_uint:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is in one of the unsigned integer formats.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_uint( const char *domain, VipsImage *im )
{
	if( !vips_band_format_isuint( im->BandFmt ) ) {
		vips_error( domain, 
			"%s", _( "image must be unsigned integer" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_8or16:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is 8 or 16-bit integer, signed or unsigned.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_8or16( const char *domain, VipsImage *im )
{
	if( im->BandFmt != VIPS_FORMAT_UCHAR &&
		im->BandFmt != VIPS_FORMAT_USHORT &&
		im->BandFmt != VIPS_FORMAT_CHAR &&
		im->BandFmt != VIPS_FORMAT_SHORT ) {
		vips_error( domain, "%s", 
			_( "image must be 8- or 16-bit integer, "
				"signed or unsigned" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_u8or16:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is 8 or 16-bit unsigned integer.
 * Otherwise set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_u8or16( const char *domain, VipsImage *im )
{
	if( im->BandFmt != VIPS_FORMAT_UCHAR &&
		im->BandFmt != VIPS_FORMAT_USHORT ) {
		vips_error( domain, "%s", 
			_( "image must be 8- or 16-bit unsigned integer" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_u8or16orf:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is 8 or 16-bit unsigned integer, or float.
 * Otherwise set an error message and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_u8or16orf( const char *domain, VipsImage *im )
{
	if( im->BandFmt != VIPS_FORMAT_UCHAR &&
		im->BandFmt != VIPS_FORMAT_USHORT &&
		im->BandFmt != VIPS_FORMAT_FLOAT ) {
		vips_error( domain, "%s", 
			_( "image must be 8- or 16-bit unsigned integer, "
				"or float" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_uintorf:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is unsigned int or float.
 * Otherwise set an error message and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_uintorf( const char *domain, VipsImage *im )
{
	if( im->BandFmt != VIPS_FORMAT_UCHAR &&
		im->BandFmt != VIPS_FORMAT_USHORT &&
		im->BandFmt != VIPS_FORMAT_UINT &&
		im->BandFmt != VIPS_FORMAT_FLOAT ) {
		vips_error( domain, "%s", 
			_( "image must be unsigned int or float" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_size_same:
 * @domain: the originating domain for the error message
 * @im1: first image to check
 * @im2: second image to check
 *
 * Check that the images have the same size.
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_size_same( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->Xsize != im2->Xsize || im1->Ysize != im2->Ysize ) {
		vips_error( domain, "%s", _( "images must match in size" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_oddsquare:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is square and that the sides are odd. 
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_oddsquare( const char *domain, VipsImage *im )
{
	if( im->Xsize != im->Ysize || 
		im->Xsize % 2 == 0 ) { 
		vips_error( domain, 
			"%s", _( "images must be odd and square" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_bands_same:
 * @domain: the originating domain for the error message
 * @im1: first image to check
 * @im2: second image to check
 *
 * Check that the images have the same number of bands.
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_bands_same( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->Bands != im2->Bands ) {
		vips_error( domain, "%s", 
			_( "images must have the same number of bands" ) ); 
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_bandno:
 * @domain: the originating domain for the error message
 * @im: image to check
 * @bandno: band number
 *
 * @bandno should be a valid band number (ie. 0 to im->Bands - 1), or can be
 * -1, meaning all bands. 
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_bandno( const char *domain, VipsImage *im, int bandno )
{
	if( bandno < -1 ||
		bandno > im->Bands - 1 ) {
		vips_error( domain, "bandno must be -1, or less than %d",
			im->Bands );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_format_same:
 * @domain: the originating domain for the error message
 * @im1: first image to check
 * @im2: second image to check
 *
 * Check that the images have the same format.
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_format_same( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->BandFmt != im2->BandFmt ) {
		vips_error( domain, "%s", 
			_( "images must have the same band format" ) ); 
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_coding_same:
 * @domain: the originating domain for the error message
 * @im1: first image to check
 * @im2: second image to check
 *
 * Check that the images have the same coding.
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_coding_same( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->Coding != im2->Coding ) {
		vips_error( domain, "%s", 
			_( "images must have the same coding" ) ); 
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_vector_length:
 * @domain: the originating domain for the error message
 * @n: number of elements in vector
 * @len: number of elements vector should have
 *
 * Check that @n == @len. 
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_vector_length( const char *domain, int n, int len )
{
	if( n != len ) {
		vips_error( domain, _( "vector must have %d elements" ), len );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_vector:
 * @domain: the originating domain for the error message
 * @n: number of elements in vector
 * @im: image to check against
 *
 * Operations with a vector constant need a 1-element vector, or a vector with
 * the same number of elements as there are bands in the image.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_vector( const char *domain, int n, VipsImage *im )
{
	if( n != 1 && im->Bands != 1 && n != im->Bands ) {
		vips_error( domain, 
			_( "vector must have 1 or %d elements" ), im->Bands );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_hist:
 * @domain: the originating domain for the error message
 * @im: image to check 
 *
 * Histogram images must have width or height 1, and must not have more than 
 * 65536 elements. Return 0 if the image will pass as a histogram, or -1 and
 * set an error message otherwise.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_hist( const char *domain, VipsImage *im )
{
	if( im->Xsize != 1 && im->Ysize != 1 ) {
		vips_error( domain, "%s", 
			_( "histograms must have width or height 1" ) );
		return( -1 );
	}
	if( VIPS_IMAGE_N_PELS( im ) > 65536 ) {
		vips_error( domain, "%s", 
			_( "histograms must have not have more than "
				"65536 elements" ) );
		return( -1 );
	}

	return( 0 );
}

/** 
 * vips_check_matrix: 
 * @domain: the originating domain for the error message
 * @im: image to check 
 * @out: put image as in-memory doubles here
 *
 * Matrix images must have width and height less than 100000 and have 1 band.
 *
 * Return 0 if the image will pass as a matrix, or -1 and set an error 
 * message otherwise.
 *
 * @out is set to be @im cast to double and stored in memory. Use
 * VIPS_MATRIX() to address values in @out. 
 *
 * You must unref @out when you are done with it.
 *
 * See also: VIPS_MATRIX(), vips_object_local()
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_matrix( const char *domain, VipsImage *im, VipsImage **out )
{
	*out = NULL;

	if( im->Xsize > 100000 || 
		im->Ysize > 100000 ) {
		vips_error( domain, "%s", _( "matrix image too large" ) );
		return( -1 );
	}
	if( im->Bands != 1 ) {
		vips_error( domain, 
			"%s", _( "matrix image must have one band" ) ); 
		return( -1 );
	}

	if( vips_cast( im, out, VIPS_FORMAT_DOUBLE, NULL ) )
                return( -1 );
        if( vips_image_wio_input( *out ) )
                return( -1 );

	return( 0 );
}

/**
 * vips_check_separable:
 * @domain: the originating domain for the error message
 * @im: image to check 
 *
 * Separable matrix images must have width or height 1.
 * Return 0 if the image will pass, or -1 and
 * set an error message otherwise.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_separable( const char *domain, VipsImage *im )
{
	if( im->Xsize != 1 && 
		im->Ysize != 1 ) {
		vips_error( domain, 
			"%s", _( "separable matrix images must have "
			"width or height 1" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_imask: (skip)
 * @domain: the originating domain for the error message
 * @mask: mask to check
 *
 * Sanity-check a mask parameter.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_imask( const char *domain, INTMASK *mask )
{
	if( !mask || 
		mask->xsize > 1000 || 
		mask->ysize > 1000 || 
		mask->xsize <= 0 || 
		mask->ysize <= 0 || 
		mask->scale == 0 || 
		!mask->coeff ) {
		vips_error( domain, "%s", _( "nonsense mask parameters" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_dmask: (skip)
 * @domain: the originating domain for the error message
 * @mask: mask to check
 *
 * Sanity-check a mask parameter.
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_dmask( const char *domain, DOUBLEMASK *mask )
{
	if( !mask || 
		mask->xsize > 1000 || 
		mask->ysize > 1000 || 
		mask->xsize <= 0 || 
		mask->ysize <= 0 || 
		mask->scale == 0 || 
		!mask->coeff ) {
		vips_error( domain, "%s", _( "nonsense mask parameters" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_check_dmask_1d: (skip)
 * @domain: the originating domain for the error message
 * @mask: mask to check
 *
 * A mask must be one-dimensional (width or height 1).
 *
 * See also: vips_error().
 *
 * Returns: 0 if OK, -1 otherwise.
 */
int
vips_check_dmask_1d( const char *domain, DOUBLEMASK *mask )
{
	if( vips_check_dmask( domain, mask ) )
		return( -1 );
	if( mask->xsize != 1 &&
		mask->ysize != 1 ) {
		vips_error( domain, "%s", _( "mask must be 1D" ) );
		return( -1 );
	}

	return( 0 );
}
