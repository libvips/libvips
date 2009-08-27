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
 * 	- image format stuff broken out 
 * 29/7/09
 * 	- check funcs added
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
#include <ctype.h>
#include <stdlib.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif /*HAVE_SYS_PARAM_H*/
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#ifdef HAVE_IO_H
#include <io.h>
#endif /*HAVE_IO_H*/
#include <string.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Test BandFmt.
 */
int
im_isint( IMAGE *im )
{	
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:
	case IM_BANDFMT_CHAR:
	case IM_BANDFMT_USHORT:
	case IM_BANDFMT_SHORT:
	case IM_BANDFMT_UINT:
	case IM_BANDFMT_INT:
		return( 1 );

	case IM_BANDFMT_FLOAT:
	case IM_BANDFMT_DOUBLE:	
	case IM_BANDFMT_COMPLEX:
	case IM_BANDFMT_DPCOMPLEX:	
		return( 0 );
	
	default:
		error_exit( "im_isint: unknown image BandFmt" );
		/*NOTREACHED*/
		return( -1 );
	}
}

/* Test endianness of an image. SPARC is MSB first
 */
int
im_isMSBfirst( IMAGE *im )
{	
	if( im->magic == IM_MAGIC_SPARC )
		return( 1 );
	else
		return( 0 );
}

/* Test this processor for endianness. True for SPARC order.
 */
int
im_amiMSBfirst( void )
{
        int test;
        unsigned char *p = (unsigned char *) &test;

        test = 0;
        p[0] = 255;

        if( test == 255 )
                return( 0 );
        else
                return( 1 );
}

int
im_isuint( IMAGE *im )
{	
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:
	case IM_BANDFMT_USHORT:
	case IM_BANDFMT_UINT:
		return( 1 );

	case IM_BANDFMT_INT:
	case IM_BANDFMT_SHORT:
	case IM_BANDFMT_CHAR:
	case IM_BANDFMT_FLOAT:
	case IM_BANDFMT_DOUBLE:	
	case IM_BANDFMT_COMPLEX:
	case IM_BANDFMT_DPCOMPLEX:	
		return( 0 );
	
	default:
		error_exit( "im_isuint: unknown image BandFmt" );
		/*NOTREACHED*/
		return( -1 );
	}
}

int
im_isfloat( IMAGE *im )
{	
	switch( im->BandFmt ) {
	case IM_BANDFMT_FLOAT:
	case IM_BANDFMT_DOUBLE:	
		return( 1 );

	case IM_BANDFMT_UCHAR:
	case IM_BANDFMT_CHAR:
	case IM_BANDFMT_USHORT:
	case IM_BANDFMT_SHORT:
	case IM_BANDFMT_UINT:
	case IM_BANDFMT_INT:
	case IM_BANDFMT_COMPLEX:
	case IM_BANDFMT_DPCOMPLEX:	
		return( 0 );
	
	default:
		error_exit( "im_isfloat: unknown image BandFmt" );
		/*NOTREACHED*/
		return( -1 );
	}
}

int
im_isscalar( IMAGE *im )
{	
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:
	case IM_BANDFMT_CHAR:
	case IM_BANDFMT_USHORT:
	case IM_BANDFMT_SHORT:
	case IM_BANDFMT_UINT:
	case IM_BANDFMT_INT:
	case IM_BANDFMT_FLOAT:
	case IM_BANDFMT_DOUBLE:	
		return( 1 );

	case IM_BANDFMT_COMPLEX:
	case IM_BANDFMT_DPCOMPLEX:	
		return( 0 );
	
	default:
		error_exit( "im_isscalar: unknown image BandFmt" );
		/*NOTREACHED*/
		return( -1 );
	}
}

int
im_iscomplex( IMAGE *im )
{	
	switch( im->BandFmt ) {
	case IM_BANDFMT_COMPLEX:
	case IM_BANDFMT_DPCOMPLEX:	
		return( 1 );

	case IM_BANDFMT_UCHAR:
	case IM_BANDFMT_CHAR:
	case IM_BANDFMT_USHORT:
	case IM_BANDFMT_SHORT:
	case IM_BANDFMT_UINT:
	case IM_BANDFMT_INT:
	case IM_BANDFMT_FLOAT:
	case IM_BANDFMT_DOUBLE:	
		return( 0 );
	
	default:
		error_exit( "im_iscomplex: unknown image BandFmt" );
		/*NOTREACHED*/
		return( -1 );
	}
}

/* Test for file exists.
 */
int
im_existsf( const char *name, ... )
{
        va_list ap;
        char buf1[PATH_MAX];

        va_start( ap, name );
        (void) im_vsnprintf( buf1, PATH_MAX - 1, name, ap );
        va_end( ap );

        /* Try that.
         */
        if( !access( buf1, R_OK ) )
                return( 1 );

        return( 0 );
}

/* True if this IMAGE is a disc file of some sort.
 */
int 
im_isfile( IMAGE *im )
{
	switch( im->dtype ) {
	case IM_MMAPIN:
	case IM_MMAPINRW:
	case IM_OPENOUT:
	case IM_OPENIN:
		return( 1 );

	case IM_PARTIAL:
	case IM_SETBUF:
	case IM_SETBUF_FOREIGN:
	case IM_NONE:
		return( 0 );

	default:
		error_exit( "im_isfile: corrupt IMAGE descriptor" );
		/*NOTREACHED*/
		return( -1 );
	}
}

/* True if this IMAGE is a partial of some sort.
 */
int 
im_ispartial( IMAGE *im )
{
	switch( im->dtype ) {
	case IM_PARTIAL:
		return( 1 );

	case IM_SETBUF:
	case IM_SETBUF_FOREIGN:
	case IM_MMAPIN:
	case IM_MMAPINRW:
	case IM_OPENIN:
	case IM_OPENOUT:
	case IM_NONE:
		return( 0 );

	default:
		error_exit( "im_ispartial: corrupt IMAGE descriptor" );
		/*NOTREACHED*/
		return( -1 );
	}
}

/* True if an int is a power of two ... 1, 2, 4, 8, 16, 32, etc. Do with just
 * integer arithmetic for portability. A previous Nicos version using doubles
 * and log/log failed on x86 with rounding problems. Return 0 for not
 * power of two, otherwise return the position of the set bit (numbering with
 * bit 1 as the lsb).
 */
int
im_ispoweroftwo( int p )
{
	int i, n;

	/* Count set bits. Could use a LUT, I guess.
	 */
	for( i = 0, n = 0; p; i++, p >>= 1 )
		if( p & 1 )
			n++;

	/* Should be just one set bit.
	 */
	if( n == 1 )
		/* Return position of bit.
		 */
		return( i );
	else
		return( 0 );
}

int
im_isvips( const char *filename )
{
	unsigned char buf[4];

	if( im__get_bytes( filename, buf, 4 ) ) {
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
im_check_uncoded( const char *domain, IMAGE *im )
{
	if( im->Coding != IM_CODING_NONE ) {
		im_error( domain, "%s", _( "image must be uncoded" ) );
		return( -1 );
	}

	return( 0 );
}

int
im_check_bands_1orn( const char *domain, IMAGE *im1, IMAGE *im2 )
{
	if( im1->Bands != im2->Bands &&
		(im1->Bands != 1 && im2->Bands != 1) ) {
		im_error( domain, "%s", 
			_( "images must have the same number of bands, "
			"or one muct be single-band" ) );
		return( -1 );
	}

	return( 0 );
}

int
im_check_noncomplex( const char *domain, IMAGE *im )
{
	if( im_iscomplex( im ) ) {
		im_error( domain, "%s", _( "image must be non-complex" ) );
		return( -1 );
	}

	return( 0 );
}

int
im_check_complex( const char *domain, IMAGE *im )
{
	if( !im_iscomplex( im ) ) {
		im_error( domain, "%s", _( "image must be complex" ) );
		return( -1 );
	}

	return( 0 );
}

int
im_check_int( const char *domain, IMAGE *im )
{
	if( !im_isint( im ) ) {
		im_error( domain, "%s", _( "image must be integer" ) );
		return( -1 );
	}

	return( 0 );
}

int
im_check_size( const char *domain, IMAGE *im1, IMAGE *im2 )
{
	if( im1->Xsize != im2->Xsize || im1->Ysize != im2->Ysize ) {
		im_error( domain, "%s", _( "images must match in size" ) );
		return( -1 );
	}

	return( 0 );
}

int
im_check_bands( const char *domain, IMAGE *im1, IMAGE *im2 )
{
	if( im1->Bands != im2->Bands ) {
		im_error( domain, "%s", 
			_( "images must have the same number of bands" ) ); 
		return( -1 );
	}

	return( 0 );
}

int
im_check_format( const char *domain, IMAGE *im1, IMAGE *im2 )
{
	if( im1->BandFmt != im2->BandFmt ) {
		im_error( domain, "%s", 
			_( "images must have the same band format" ) ); 
		return( -1 );
	}

	return( 0 );
}

int
im_check_vector( const char *domain, int n, IMAGE *im )
{
	if( n != 1 && n != im->Bands ) {
		im_error( domain, 
			_( "vector must have 1 or %d elements" ), im->Bands );
		return( -1 );
	}

	return( 0 );
}
