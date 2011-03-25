/* check VipsImages in various ways
 *
 * im_iocheck()
 * Copyright: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 
 * 15/4/93 JC
 *	- im_incheck(), im_outcheck() added.
 *	- type field now checked.
 * 10/6/93 JC
 *	- auto-fallback to old-style input added
 * 6/6/95 JC
 *	- revised and improved fallback code
 *
 * im_rwcheck()
 * Copyright: John Cupitt
 * Written on: 17/6/92
 * Updated on:
 * 15/4/93
 *	- checks for partial images added
 *	- now uses type field
 * 31/8/93 JC
 *	- returns ok for VIPS_IMAGE_MMAPINRW type files now too
 *	- returns -1 rather than 1 on error
 *	- ANSIfied
 * 1/10/97 JC
 *	- moved here, and renamed im_rwcheck()
 * 13/2/01 JC
 *	- im_image_sanity() checks added
 *
 * im_piocheck()
 * 10/6/93 J.Cupitt
 * 	- im_iocheck() adapted to make im_piocheck()
 * 	- auto-rewind feature added
 * 27/10/95 JC
 *	- im_pincheck() on a setbuf now zaps generate function so as not to
 *	  confuse any later calls to im_prepare() or im_prepare_inplace()
 *
 * 12/10/09
 * 	- all the above rolled into this file
 * 	- plus chunks of predicate.c
 * 	- gtkdoc comments
 * 25/3/11
 * 	- move to vips_ namespace
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
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif /*HAVE_SYS_FILE_H*/

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: check
 * @short_description: test images for various properties
 * @stability: Stable
 * @see_also: <link linkend="libvips-imagE">image</link>
 * @include: vips/vips.h
 *
 * These functions perform simple checks on an #VipsImage, or indicate that you
 * intend to use an #VipsImage in a certain way.
 *
 * vips_incheck(), vips_pincheck() and friends indicate the image IO style you
 * intend to use, transforming the underlying #VipsImage structure if
 * necessary.
 *
 * vips_check_mono() and friends and convenience functions that test an 
 * #VipsImage 
 * for having various properties
 * and signal an error if the condition is not met. They are useful for
 * writing image processing operations which can only work on certain types of
 * image.
 */

/**
 * im_check_uncoded:
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
im_check_uncoded( const char *domain, VipsImage *im )
{
	if( im->Coding != VIPS_CODING_NONE ) {
		vips_error( domain, "%s", _( "image must be uncoded" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_coding_noneorlabq:
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
im_check_coding_noneorlabq( const char *domain, VipsImage *im )
{
	/* These all have codings that extract/ifthenelse/etc can ignore.
	 */
	if( im->Coding != VIPS_CODING_NONE && 
		im->Coding != VIPS_CODING_LABQ ) {
		vips_error( domain, 
			"%s", _( "image coding must be NONE or LABQ" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_coding_known:
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
im_check_coding_known( const char *domain, VipsImage *im )
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
 * im_check_coding_rad:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is in Radiance coding. 
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
im_check_coding_rad( const char *domain, VipsImage *im )
{
	if( im->Coding != VIPS_CODING_RAD ||
		im->BandFmt != VIPS_FORMAT_UCHAR || 
		im->Bands != 4 ) { 
		vips_error( domain, "%s", _( "Radiance coding only" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_coding_labq:
 * @domain: the originating domain for the error message
 * @im: image to check
 *
 * Check that the image is in LABQ coding. 
 * If not, set an error message
 * and return non-zero.
 *
 * See also: vips_error().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
im_check_coding_labq( const char *domain, VipsImage *im )
{
	if( im->Coding != VIPS_CODING_LABQ ||
		im->BandFmt != VIPS_FORMAT_UCHAR || 
		im->Bands != 4 ) { 
		vips_error( domain, "%s", _( "LABQ coding only" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_mono:
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
im_check_mono( const char *domain, VipsImage *im )
{
	if( im->Bands != 1 ) {
		vips_error( domain, "%s", _( "image must one band" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_bands:
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
im_check_bands( const char *domain, VipsImage *im, int bands )
{
	if( im->Bands != bands ) {
		vips_error( domain, _( "image must have %d bands" ), bands );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_1or3:
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
im_check_bands_1or3( const char *domain, VipsImage *im )
{
	if( im->Bands != 1 && im->Bands != 3 ) {
		vips_error( domain, "%s", 
			_( "image must have one or three bands" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_bands_1orn:
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
im_check_bands_1orn( const char *domain, VipsImage *im1, VipsImage *im2 )
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
 * im_check_bands_1orn_unary:
 * @domain: the originating domain for the error message
 * @im: image to check
 * @n: number of bands, or 1
 *
 * Check that an image has 1 or @n bands. Handy for unary operations, cf.
 * im_check_bands_1orn().
 * If not, set an error message
 * and return non-zero.
 *
 * See also: im_check_bands_1orn().
 *
 * Returns: 0 on OK, or -1 on error.
 */
int
im_check_bands_1orn_unary( const char *domain, VipsImage *im, int n )
{
	if( im->Bands != 1 && im->Bands != n ) { 
		vips_error( domain, _( "image must have 1 or %d bands" ), n );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_noncomplex:
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
im_check_noncomplex( const char *domain, VipsImage *im )
{
	if( vips_bandfmt_iscomplex( im->BandFmt ) ) {
		vips_error( domain, "%s", _( "image must be non-complex" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_complex:
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
im_check_complex( const char *domain, VipsImage *im )
{
	if( !vips_bandfmt_iscomplex( im->BandFmt ) ) {
		vips_error( domain, "%s", _( "image must be complex" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_format:
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
im_check_format( const char *domain, VipsImage *im, VipsBandFormat fmt )
{
	if( im->BandFmt != fmt ) {
		vips_error( domain, 
			_( "image must be %s" ), 
			VIPS_ENUM_STRING( VIPS_TYPE_BAND_FORMAT, fmt ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_int:
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
im_check_int( const char *domain, VipsImage *im )
{
	if( !vips_bandfmt_isint( im->BandFmt ) ) {
		vips_error( domain, "%s", _( "image must be integer" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_uint:
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
im_check_uint( const char *domain, VipsImage *im )
{
	if( !vips_bandfmt_isuint( im->BandFmt ) ) {
		vips_error( domain, "%s", _( "image must be unsigned integer" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_8or16:
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
im_check_8or16( const char *domain, VipsImage *im )
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
 * im_check_u8or16:
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
im_check_u8or16( const char *domain, VipsImage *im )
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
 * im_check_u8or16orf:
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
im_check_u8or16orf( const char *domain, VipsImage *im )
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
 * im_check_uintorf:
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
im_check_uintorf( const char *domain, VipsImage *im )
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
 * im_check_size_same:
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
im_check_size_same( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->Xsize != im2->Xsize || im1->Ysize != im2->Ysize ) {
		vips_error( domain, "%s", _( "images must match in size" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_bands_same:
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
im_check_bands_same( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->Bands != im2->Bands ) {
		vips_error( domain, "%s", 
			_( "images must have the same number of bands" ) ); 
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_bandno:
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
im_check_bandno( const char *domain, VipsImage *im, int bandno )
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
 * im_check_format_same:
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
im_check_format_same( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->BandFmt != im2->BandFmt ) {
		vips_error( domain, "%s", 
			_( "images must have the same band format" ) ); 
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_coding_same:
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
im_check_coding_same( const char *domain, VipsImage *im1, VipsImage *im2 )
{
	if( im1->Coding != im2->Coding ) {
		vips_error( domain, "%s", 
			_( "images must have the same coding" ) ); 
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_vector:
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
im_check_vector( const char *domain, int n, VipsImage *im )
{
	if( n != 1 && im->Bands != 1 && n != im->Bands ) {
		vips_error( domain, 
			_( "vector must have 1 or %d elements" ), im->Bands );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_hist:
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
im_check_hist( const char *domain, VipsImage *im )
{
	if( im->Xsize != 1 && im->Ysize != 1 ) {
		vips_error( domain, "%s", 
			_( "histograms must have width or height 1" ) );
		return( -1 );
	}
	if( im->Xsize * im->Ysize > 65536 ) {
		vips_error( domain, "%s", 
			_( "histograms must have not have more than "
				"65536 elements" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_imask:
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
im_check_imask( const char *domain, INTMASK *mask )
{
	if( !mask || 
		mask->xsize > 1000 || 
		mask->ysize > 1000 || 
		mask->xsize <= 0 || 
		mask->ysize <= 0 || 
		!mask->coeff ) {
		vips_error( "im_conv", "%s", _( "nonsense mask parameters" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_check_dmask:
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
im_check_dmask( const char *domain, DOUBLEMASK *mask )
{
	if( !mask || 
		mask->xsize > 1000 || 
		mask->ysize > 1000 || 
		mask->xsize <= 0 || 
		mask->ysize <= 0 || 
		!mask->coeff ) {
		vips_error( "im_conv", "%s", _( "nonsense mask parameters" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_bandfmt_isint:
 * @fmt: format to test
 *
 * Return %TRUE if @fmt is one of the integer types.
 */
gboolean
vips_bandfmt_isint( VipsBandFormat fmt )
{
	switch( fmt ) {
	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_INT:
		return( TRUE );

	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:	
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:	
		return( FALSE );
	
	default:
		g_assert( 0 );
		return( -1 );
	}
}

/**
 * vips_bandfmt_isuint:
 * @fmt: format to test
 *
 * Return %TRUE if @fmt is one of the unsigned integer types.
 */
gboolean
vips_bandfmt_isuint( VipsBandFormat fmt )
{
	switch( fmt ) {
	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_UINT:
		return( 1 );

	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:	
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:	
		return( 0 );
	
	default:
		g_assert( 0 );
		return( -1 );
	}
}

/**
 * vips_bandfmt_isfloat:
 * @fmt: format to test
 *
 * Return %TRUE if @fmt is one of the float types.
 */
gboolean
vips_bandfmt_isfloat( VipsBandFormat fmt )
{
	switch( fmt ) {
	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:	
		return( 1 );

	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:	
		return( 0 );
	
	default:
		g_assert( 0 );
		return( -1 );
	}
}

/**
 * vips_bandfmt_iscomplex:
 * @fmt: format to test
 *
 * Return %TRUE if @fmt is one of the complex types.
 */
gboolean
vips_bandfmt_iscomplex( VipsBandFormat fmt )
{
	switch( fmt ) {
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:	
		return( 1 );

	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:	
		return( 0 );
	
	default:
		g_assert( 0 );
		return( -1 );
	}
}
