/* Test various predicates.
 * 
 * J.Cupitt, 8/4/93.
 * 13/10/95 JC
 *	- ANSIfied
 *	- im_ispoweroftwo() added
 * 14/11/96 Jc
 *	- im_isjpeg() added
 * 25/3/97 JC
 * 	- im_isvips() added
 * 14/4/97 JC
 * 	- im_istifftiled() added
 * 29/10/98 JC
 *	- im_isMSBfirst() and im_amiMSBfirst() added
 * 16/6/99 JC
 *	- added im_existsf()
 * 22/11/00 JC
 *	- added im_isppm()
 * 23/4/01 JC
 *	- HAVE_TIFF turns on TIFFness
 * 19/10/02 HB
 *      - PNG added
 * 1/5/06
 * 	- added exr
 * 3/8/07
 * 	- cleanups
 * 22/5/08
 * 	- now just formats
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <vips/vips.h>

#ifdef HAVE_TIFF
#include <tiffio.h>
#endif /*HAVE_TIFF*/

#ifdef HAVE_PNG
#include <png.h>
#endif /*HAVE_PNG*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Read a few bytes from the start of a file. For sniffing file types.
 */
static int
get_bytes( const char *filename, unsigned char buf[], int len )
{
	int fd;

	/* File may not even exist (for tmp images for example!)
	 * so no hasty messages. And the file might be truncated, so no error
	 * on read either.
	 */
#ifdef BINARY_OPEN
	if( (fd = open( filename, O_RDONLY | O_BINARY )) == -1 )
#else /*BINARY_OPEN*/
	if( (fd = open( filename, O_RDONLY )) == -1 )
#endif /*BINARY_OPEN*/
		return( 0 );
	if( read( fd, buf, len ) != len ) {
		close( fd );
		return( 0 );
	}
	close( fd );

	return( 1 );
}

int
im_istiff( const char *filename )
{
	unsigned char buf[2];

	if( get_bytes( filename, buf, 2 ) )
		if( (buf[0] == 'M' && buf[1] == 'M') ||
			(buf[0] == 'I' && buf[1] == 'I') ) 
			return( 1 );

	return( 0 );
}

#ifdef HAVE_PNG
int
im_ispng( const char *filename )
{
	unsigned char buf[8];

	return( get_bytes( filename, buf, 8 ) &&
		!png_sig_cmp( buf, 0, 8 ) );
}
#else /*HAVE_PNG*/
int
im_ispng( const char *filename )
{
	return( 0 );
}
#endif /*HAVE_PNG*/

#ifdef HAVE_MAGICK
int
im_ismagick( const char *filename )
{
	IMAGE *im;
	int result;

	if( !(im = im_open( "dummy", "p" )) )
		return( -1 );
	result = im_magick2vips_header( filename, im );
	im_clear_error_string();
	im_close( im );

	return( result == 0 );
}
#else /*HAVE_MAGICK*/
int
im_ismagick( const char *filename )
{
	return( 0 );
}
#endif /*HAVE_MAGICK*/

int
im_isppm( const char *filename )
{
	unsigned char buf[2];

	if( get_bytes( filename, buf, 2 ) )
		if( buf[0] == 'P' && (buf[1] >= '1' || buf[1] <= '6') )
			return( 1 );

	return( 0 );
}

#ifdef HAVE_TIFF

/* Handle TIFF errors here. 
 */
static void 
vhandle( char *module, char *fmt, ... )
{
	va_list ap;

	im_error( "im_istifftiled", _( "TIFF error in \"%s\": " ), module );

	va_start( ap, fmt );
	im_verrormsg( fmt, ap );
	va_end( ap );
}

int
im_istifftiled( const char *filename )
{
	TIFF *tif;
	int tiled;

	/* Override the default TIFF error handler.
	 */
	TIFFSetErrorHandler( (TIFFErrorHandler) vhandle );

#ifdef BINARY_OPEN
	if( !(tif = TIFFOpen( filename, "rb" )) ) {
#else /*BINARY_OPEN*/
	if( !(tif = TIFFOpen( filename, "r" )) ) {
#endif /*BINARY_OPEN*/
		/* Not a TIFF file ... return False.
		 */
		im_clear_error_string();
		return( 0 );
	}
	tiled = TIFFIsTiled( tif );
	TIFFClose( tif );

	return( tiled );
}

#else /*HAVE_TIFF*/

int
im_istifftiled( const char *filename )
{
	return( 0 );
}

#endif /*HAVE_TIFF*/

int
im_isjpeg( const char *filename )
{
	unsigned char buf[2];

	if( get_bytes( filename, buf, 2 ) )
		if( (int) buf[0] == 0xff && (int) buf[1] == 0xd8 )
			return( 1 );

	return( 0 );
}

int
im_isvips( const char *filename )
{
	unsigned char buf[4];

	if( get_bytes( filename, buf, 4 ) ) {
		if( buf[0] == 0x08 && buf[1] == 0xf2 &&
			buf[2] == 0xa6 && buf[3] == 0xb6 )
			/* SPARC-order VIPS image.
			 */
			return( 1 );
		else if( buf[3] == 0x08 && buf[2] == 0xf2 &&
			buf[1] == 0xa6 && buf[0] == 0xb6 )
			/* INTEL-order VIPS image.
			 */
			return( 1 );
	}

	return( 0 );
}

int
im_isexr( const char *filename )
{
	unsigned char buf[4];

	if( get_bytes( filename, buf, 4 ) )
		if( buf[0] == 0x76 && buf[1] == 0x2f &&
			buf[2] == 0x31 && buf[3] == 0x01 )
			return( 1 );

	return( 0 );
}

