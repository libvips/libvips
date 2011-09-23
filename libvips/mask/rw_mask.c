/* read and write masks
 */

/* Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 29/04/1991
 * Modified on: 10/8/1992, J.Cupitt
 *    -	Mask reading routines no longer fail if scale and offset are missing.
 *	Instead, they set default values of scale=1, offset=0.
 *    - Code tidied up, better error recovery.
 *    -	Bugs fixed in im_dup_*mask. No longer coredump.
 *    -	Bugs fixed in im_write_*mask. Now work for non-square matricies.
 *    -	im_copy_*mask_matrix, im_copy_matrix_*mask added: copy VIPS mask 
 *	structures into Numerical Recipies in C style matricies and vice
 *	versa. Both structures should have been built before copy attempted.
 *	See im_create_*mask, im_*mat_alloc. The matrix should be indexed by 0 
 *	to size-1.
 * 9/7/93 JC
 *    - some ANSIfication and tidies
 *    -	im_free_*mask() now return zero, so they can be used as close
 *	callbacks.
 * 7/10/94 JC
 *    - new IM_NEW(), IM_ARRAY() macros added
 * 27/4/95 JC
 *    -	oops! forgot to init IM_ARRAY() memory to zero
 * 7/8/96 JC
 *    - im_scale_dmask() rewritten
 * 7/5/98 JC
 *    - im_read_*mask() rewritten, now more robust
 *    - im_write_*mask() rewritten
 *    - new functions im_write_*mask_name()
 * 28/7/99 JC
 *    -	im_create_imaskv(), im_create_dmaskv() make masks and init from
 *	varargs
 *    - tabs allowed as column separators
 * 9/2/05
 *    - "," allowed as column separator ... helps CSV read
 * 31/5/06
 *    - use g_ascii_strtod() and friends
 * 2006-09-08 tcv
 *    - add im_norm_dmask()
 * 1/9/09
 * 	- move im_print_*mask() here
 * 12/11/09
 * 	- reading a float mask with im_read_imask() produced an incorrect 
 * 	  error messagge
 * 21/10/10
 * 	- gtk-doc
 * 	- you can use commas to separate header fields
 * 	- small cleanups
 * 30/11/10
 * 	- im_scale_dmask() normalises to 20, not 100 ... we hit the fast
 * 	  conv path more often
 * 24/1/10
 * 	- oops, missing braces in write dmask removed spaces between items
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
#include <stdarg.h>
#include <string.h>
#include <math.h>

#include <vips/vips.h>

/**
 * SECTION: mask
 * @short_description: load, save and process mask (matrix) objects
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations load, save and process mask objects. Masks are used as
 * paramaters to convolution and morphology operators, and to represent
 * matrices. There are two types of matrix: integer #INTMASK and double 
 * precision floating point #DOUBLEMASK.
 *
 * This API is horrible and clunky. Surely it will be replaced soon.
 */

/**
 * INTMASK:
 * @xsize: mask width
 * @ysize: mask height
 * @scale: mask scale factor
 * @offset: mask offset
 * @coeff: array of mask elements
 * @filename: the file this mask was read from, or should be written to
 *
 * An integer mask. 
 *
 * @scale lets the mask represent fractional values: for
 * example, in integer convolution (see im_conv()) the result of the
 * convolution is divided by @scale and then added to @offset before being 
 * written to the output image.
 *
 * @scale and @offset default to 1 and 0. Various functions, such as
 * im_conv(), will fail if @scale is zero.
 *
 * You can read and write the matrix elements in @coeff.
 */

/**
 * DOUBLEMASK:
 * @xsize: mask width
 * @ysize: mask height
 * @scale: mask scale factor
 * @offset: mask offset
 * @coeff: array of mask elements
 * @filename: the file this mask was read from, or should be written to
 *
 * A floating-point mask. 
 *
 * As with #INTMASK, in convolution (see im_convf()) the result of the
 * convolution is divided by @scale and then added to @offset before being 
 * written to the output image.
 *
 * @scale and @offset default to 1.0 and 0.0. Various functions, such as
 * im_conv(), will fail if @scale is zero.
 *
 * You can read and write the matrix elements in @coeff.
 */

/* Size of line buffer for reading.
 */
#define MAX_LINE (32768)

/**
 * im_free_imask:
 * @in: mask to free
 *
 * Free mask structure and any attached arrays. Return zero, so we can use
 * these functions as close callbacks.
 *
 * See also: im_free_dmask().
 *
 * Returns: zero.
 */
int
im_free_imask( INTMASK *in )
{	
	if( !in )
		return( 0 );

	IM_FREE( in->coeff );
	IM_FREE( in->filename );
	IM_FREE( in );

	return( 0 );
}

/**
 * im_free_dmask:
 * @in: mask to free
 *
 * Free mask structure and any attached arrays. Return zero, so we can use
 * these functions as close callbacks.
 *
 * See also: im_free_dmask().
 *
 * Returns: zero.
 */
int
im_free_dmask( DOUBLEMASK *in )
{
	if( !in )
		return( 0 );

	IM_FREE( in->coeff );
	IM_FREE( in->filename );
	IM_FREE( in );

	return( 0 );
}

/**
 * im_create_imask:
 * @filename: set mask filename to this
 * @xsize: mask width
 * @ysize: mask height
 *
 * Create an empty imask. You need to loop over @coeff to set the values. 
 *
 * See also: im_create_imaskv().
 *
 * Returns: The newly-allocated mask.
 */
INTMASK *
im_create_imask( const char *filename, int xsize, int ysize )
{	
	INTMASK *out;
	int size = xsize * ysize;

	/* Check args.
	 */
	if( xsize <= 0 || ysize <= 0 || filename == NULL ) { 
		im_error( "im_create_imask", "%s", _( "bad arguments" ) ); 
		return( NULL );
	}

	/* Allocate and initialise structure.
	 */
	if( !(out = IM_NEW( NULL, INTMASK )) ) 
		return( NULL );
	out->coeff = NULL;
	out->filename = NULL;
	out->scale = 1;
	out->offset = 0;
	out->xsize = 0;
	out->ysize = 0;

	if( !(out->coeff = IM_ARRAY( NULL, size, int )) ) {
		im_free_imask( out );
		return( NULL );
	}
	(void) memset( (char *) out->coeff, 0, size * sizeof( int ) );
	if( !(out->filename = im_strdup( NULL, filename )) ) {
		im_free_imask( out );
		return( NULL );
	}
	out->xsize = xsize; 
	out->ysize = ysize;

	return( out );
}

/**
 * im_create_imaskv:
 * @filename: set mask filename to this
 * @xsize: mask width
 * @ysize: mask height
 * @Varargs: values to set for the mask
 *
 * Create an imask and initialise it from the function parameter list.
 *
 * See also: im_create_imask().
 *
 * Returns: The newly-allocated mask.
 */
INTMASK *
im_create_imaskv( const char *filename, int xsize, int ysize, ... )
{
	va_list ap;

	INTMASK *out;
	int i;

	if( !(out = im_create_imask( filename, xsize, ysize )) )
		return( NULL );

	va_start( ap, ysize );
	for( i = 0; i < xsize * ysize; i++ )
		out->coeff[i] = va_arg( ap, int );
	va_end( ap );

	return( out );
}

/**
 * im_create_dmask:
 * @filename: set mask filename to this
 * @xsize: mask width
 * @ysize: mask height
 *
 * Create an empty dmask. You need to loop over @coeff to set the values. 
 *
 * See also: im_create_dmaskv(), im_vips2mask().
 *
 * Returns: The newly-allocated mask.
 */
DOUBLEMASK *
im_create_dmask( const char *filename, int xsize, int ysize )
{	
	DOUBLEMASK *out;
	int size = xsize * ysize;

	/* Check args.
	 */
	if( xsize <= 0 || ysize <= 0 || filename == NULL ) { 
		im_error( "im_create_dmask", "%s", _( "bad arguments" ) ); 
		return( NULL );
	}

	/* Allocate and initialise structure.
	 */
	if( !(out = IM_NEW( NULL, DOUBLEMASK )) ) 
		return( NULL );
	out->coeff = NULL;
	out->filename = NULL;
	out->scale = 1.0;
	out->offset = 0.0;
	out->xsize = 0;
	out->ysize = 0;

	if( !(out->coeff = IM_ARRAY( NULL, size, double )) ) {
		im_free_dmask( out );
		return( NULL );
	}
	(void) memset( (char *) out->coeff, 0, size * sizeof( double ) );
	if( !(out->filename = im_strdup( NULL, filename )) ) {
		im_free_dmask( out );
		return( NULL );
	}
	out->xsize = xsize; 
	out->ysize = ysize;

	return( out );
}

/**
 * im_create_dmaskv:
 * @filename: set mask filename to this
 * @xsize: mask width
 * @ysize: mask height
 * @Varargs: values to set for the mask
 *
 * Create a dmask and initialise it from the function parameter list.
 *
 * See also: im_create_dmask().
 *
 * Returns: The newly-allocated mask.
 */
DOUBLEMASK *
im_create_dmaskv( const char *filename, int xsize, int ysize, ... )
{	
	va_list ap;

	DOUBLEMASK *out;
	int i;

	if( !(out = im_create_dmask( filename, xsize, ysize )) )
		return( NULL );

	va_start( ap, ysize );
	for( i = 0; i < xsize * ysize; i++ )
		out->coeff[i] = va_arg( ap, double );
	va_end( ap );

	return( out );
}

/* Read a line from a file! 
 */
static int
get_line( FILE *fp, char *buf )
{
	if( !fgets( buf, MAX_LINE, fp ) ) {
		im_error( "read_mask", "%s", _( "unexpected EOF" ) );
		return( -1 );
	}

	return( 0 );
}

/* width, height, optional scale, optional offset.
 */
static int
read_header( FILE *fp, int *xs, int *ys, double *scale, double *offset )
{
	char buf[MAX_LINE];
	char *p, *q;
	double v[4];
	int i;

	/* Read the first line: should contain size and optional 
	 * scale + offset. 
	 */
	if( get_line( fp, buf ) ) 
		return( -1 );

	/* Read as space separated doubles. \n is in the break list because
	 * our line will (usually) have a trailing \n which we want to count
	 * as whitespace.
	 */
	p = buf; 
	for( i = 0, p = buf; 
		i < 4 && (q = im_break_token( p, " \";,\t\n" )); 
		i++, p = q ) 
		v[i] = g_ascii_strtod( p, NULL );

	if( (i != 2 && i != 4) ||
		ceil( v[0] ) != v[0] ||
		ceil( v[1] ) != v[1] ||
		v[0] <= 0 ||
		v[1] <= 0 ) {
		im_error( "read_header", 
			"%s", _( "error reading matrix header" ) );
		return( -1 );
	}
	if( i == 4 && v[2] == 0 ) {
		im_error( "read_header", 
			"%s", _( "scale should be non-zero" ) );
		return( -1 );
	}

	*xs = v[0];
	*ys = v[1];
	if( i == 2 ) {
		*scale = 1.0;
		*offset = 0.0;
	}
	else {
		*scale = v[2];
		*offset = v[3];
	}

	return( 0 );
}

/**
 * im_read_dmask:
 * @filename: read matrix from this file
 *
 * Reads a matrix from a file.
 *
 * Matrix files have a simple format that's supposed to be easy to create with
 * a text editor or a spreadsheet. 
 *
 * The first line has four numbers for width, height, scale and
 * offset (scale and offset may be omitted, in which case they default to 1.0
 * and 0.0). Scale must be non-zero. Width and height must be positive
 * integers. The numbers are separated by any mixture of spaces, commas, 
 * tabs and quotation marks ("). The scale and offset fields may be 
 * floating-point, and must use '.'
 * as a decimal separator.
 *
 * Subsequent lines each hold one line of matrix data, with numbers again
 * separated by any mixture of spaces, commas, 
 * tabs and quotation marks ("). The numbers may be floating-point, and must
 * use '.'
 * as a decimal separator.
 *
 * Extra characters at the ends of lines or at the end of the file are
 * ignored.
 *
 * See also: im_read_imask(), im_gauss_dmask().
 *
 * Returns: the loaded mask on success, or NULL on error.
 */
DOUBLEMASK *
im_read_dmask( const char *filename )
{
	FILE *fp;
	double sc, off;
	int xs, ys;
	DOUBLEMASK *out;
	int x, y, i, size;
	char buf[MAX_LINE];

	if( !(fp = im__file_open_read( filename, NULL, TRUE )) ) 
		return( NULL );

	if( read_header( fp, &xs, &ys, &sc, &off ) ) {
		fclose( fp );
		return( NULL );
	}

	if( !(out = im_create_dmask( filename, xs, ys )) ) {
		fclose( fp );
		return( NULL );
	}
	out->scale = sc;
	out->offset = off;
	size = xs * ys;

	for( i = 0, y = 0; y < ys; y++ ) {
		char *p;

		if( get_line( fp, buf ) ) {
			im_free_dmask( out );
			fclose( fp );
			return( NULL );
		}

		for( p = buf, x = 0; p && x < xs; 
			x++, i++, p = im_break_token( p, " \t,\";" ) ) 
			out->coeff[i] = g_ascii_strtod( p, NULL );
	}
	fclose( fp );

	return( out );
}

/**
 * im_read_imask:
 * @filename: read matrix from this file
 *
 * Reads an integer matrix from a file.
 *
 * This function works exactly as im_read_dmask(), but the loaded matrix is
 * checked for 'int-ness'. All coefficients must be integers, and scale and
 * offset must be integers.
 *
 * See also: im_read_dmask().
 *
 * Returns: the loaded mask on success, or NULL on error.
 */
INTMASK *
im_read_imask( const char *filename )
{
	DOUBLEMASK *dmask;
	INTMASK *imask;
	int i;

	if( !(dmask = im_read_dmask( filename )) )
		return( NULL );

	if( ceil( dmask->scale ) != dmask->scale || 
		ceil( dmask->offset ) != dmask->offset ) {
		im_error( "im_read_imask", 
			"%s", _( "scale and offset should be int" ) );
		im_free_dmask( dmask );

		return( NULL );
	}

	for( i = 0; i < dmask->xsize * dmask->ysize; i++ ) 
		if( ceil( dmask->coeff[i] ) != dmask->coeff[i] ) {
			im_error( "im_read_imask", _( "ceofficient at "
				"position (%d, %d) is not int" ), 
				i % dmask->xsize,
				i / dmask->xsize );
			im_free_dmask( dmask );

			return( NULL );
		}

	if( !(imask = im_create_imask( filename, 
		dmask->xsize, dmask->ysize )) ) {
		im_free_dmask( dmask );
		return( NULL );
	}
	imask->scale = dmask->scale;
	imask->offset = dmask->offset;
	for( i = 0; i < dmask->xsize * dmask->ysize; i++ ) 
		imask->coeff[i] = dmask->coeff[i];

	im_free_dmask( dmask );

	return( imask );
}

/**
 * im_scale_dmask:
 * @in: mask to scale
 * @filename: filename for returned mask
 *
 * Scale the dmask to make an imask with a maximum value of 20.
 *
 * See also: im_norm_dmask().
 *
 * Returns: the converted mask, or NULL on error.
 */
INTMASK *
im_scale_dmask( DOUBLEMASK *in, const char *filename )
{
	const int size = in->xsize * in->ysize;

	INTMASK *out;
	double maxval, dsum; 
	int i;
	int isum;

	if( im_check_dmask( "im_scale_dmask", in ) ||
		!(out = im_create_imask( filename, in->xsize, in->ysize )) )
		return( NULL );

	/* Find mask max.
	 */
	maxval = in->coeff[0];
	for( i = 0; i < size; i++ ) 
		if( in->coeff[i] > maxval )
			maxval = in->coeff[i];

	/* Copy and scale, setting max to 20.
	 */
	for( i = 0; i < size; i++ ) 
		out->coeff[i] = IM_RINT( in->coeff[i] * 20.0 / maxval );
	out->offset = in->offset;

	/* Set the scale to match the adjustment to max.
	 */
	isum = 0;
	dsum = 0.0;
	for( i = 0; i < size; i++ ) { 
		isum += out->coeff[i]; 
		dsum += in->coeff[i];
	}

	if( dsum == in->scale )
		out->scale = isum;
	else if( dsum == 0.0 )
		out->scale = 1.0;
	else
		out->scale = IM_RINT( in->scale * isum / dsum );

	return( out );	
}

/**
 * im_dmask2imask:
 * @in: mask to convert
 * @filename: filename for returned mask
 *
 * Make an imask from the dmask, rounding to nearest. 
 *
 * See also: im_scale_dmask().
 *
 * Returns: the converted mask, or NULL on error.
 */
INTMASK *
im_dmask2imask( DOUBLEMASK *in, const char *filename )
{
	const int size = in->xsize * in->ysize;

	INTMASK *out;
	int i;

	if( im_check_dmask( "im_dmask2imask", in ) ||
		!(out = im_create_imask( filename, in->xsize, in->ysize )) )
		return( NULL );

	for( i = 0; i < size; i++ ) 
		out->coeff[i] = IM_RINT( in->coeff[i] );
	out->offset = IM_RINT( in->offset );
	out->scale = IM_RINT( in->scale );

	return( out );	
}

/**
 * im_imask2dmask:
 * @in: mask to convert
 * @filename: filename for returned mask
 *
 * Make a dmask from the imask.
 *
 * See also: im_dmask2imask().
 *
 * Returns: the converted mask, or NULL on error.
 */
DOUBLEMASK *
im_imask2dmask( INTMASK *in, const char *filename )
{
	const int size = in->xsize * in->ysize;

	DOUBLEMASK *out;
	int i;

	if( im_check_imask( "im_imask2dmask", in ) ||
		!(out = im_create_dmask( filename, in->xsize, in->ysize )) )
		return( NULL );

	for( i = 0; i < size; i++ ) 
		out->coeff[i] = in->coeff[i];
	out->offset = in->offset;
	out->scale = in->scale;

	return( out );	
}

/**
 * im_norm_dmask:
 * @mask: mask to scale
 *
 * Normalise the dmask. Apply the scale and offset to each element to make
 * a mask with scale 1, offset zero.
 *
 * See also: im_scale_dmask().
 *
 * Returns: 0 on success, or -1 on error.
 */
void 
im_norm_dmask( DOUBLEMASK *mask )
{ 	
	const int n = mask->xsize * mask->ysize;
	const double scale = (mask->scale == 0) ? 0 : (1.0 / mask->scale);

	int i;

	if( im_check_dmask( "im_norm_dmask", mask ) ||
		(1.0 == scale && 0.0 == mask->offset) )
		return;

	for( i = 0; i < n; i++ )
		mask->coeff[i] = mask->coeff[i] * scale + mask->offset;

	mask->scale = 1.0;
	mask->offset = 0.0;
}

/**
 * im_dup_imask:
 * @in: mask to duplicate
 * @filename: filename to set for the new mask
 *
 * Duplicate an imask.
 *
 * See also: im_dup_dmask().
 *
 * Returns: the mask copy, or NULL on error.
 */
INTMASK *
im_dup_imask( INTMASK *in, const char *filename )
{
	INTMASK *out;
	int i;

	if( im_check_imask( "im_dup_imask", in ) ||
		!(out = im_create_imask( filename, in->xsize, in->ysize )) )
		return( NULL );

        out->offset = in->offset; 
	out->scale = in->scale;

        for( i = 0; i < in->xsize * in->ysize; i++ )
		out->coeff[i] = in->coeff[i];

        return( out );
}

/**
 * im_dup_dmask:
 * @in: mask to duplicate
 * @filename: filename to set for the new mask
 *
 * Duplicate a dmask.
 *
 * See also: im_dup_imask().
 *
 * Returns: the mask copy, or NULL on error.
 */
DOUBLEMASK *
im_dup_dmask( DOUBLEMASK *in, const char *filename )
{
	DOUBLEMASK *out;
	int i;

	if( im_check_dmask( "im_dup_dmask", in ) ||
		!(out = im_create_dmask( filename, in->xsize, in->ysize )) )
		return( NULL );

        out->offset = in->offset; 
	out->scale = in->scale;

        for( i = 0; i < in->xsize * in->ysize; i++ )
		out->coeff[i] = in->coeff[i];

        return( out );
}

/* Write to file.
 */
static int 
write_line( FILE *fp, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	if( !vfprintf( fp, fmt, ap ) ) {
		im_error( "write_mask", "%s", _( "write error, disc full?" ) );
		return( -1 );
	}
	va_end( ap );

	return( 0 );
}

static int 
write_double( FILE *fp, double d )
{
	char buf[G_ASCII_DTOSTR_BUF_SIZE];

	fprintf( fp, "%s", g_ascii_dtostr( buf, sizeof( buf ), d ) );

	return( 0 );
}

/**
 * im_write_imask_name:
 * @in: mask to write
 * @filename: filename to write to
 *
 * Write an imask to a file. See im_read_dmask() for a description of the mask
 * file format.
 *
 * See also: im_write_imask().
 *
 * Returns: 0 on success, or -1 on error.
 */
int 
im_write_imask_name( INTMASK *in, const char *filename )
{
	FILE *fp;
	int x, y, i;

	if( im_check_imask( "im_write_imask_name", in ) ||
		!(fp = im__file_open_write( filename, TRUE )) )
		return( -1 );

	if( write_line( fp, "%d %d", in->xsize, in->ysize ) ) {
		fclose( fp ); 
		return( -1 );
	}
	if( in->scale != 1 || in->offset != 0 ) 
		write_line( fp, " %d %d", in->scale, in->offset );
	write_line( fp, "\n" );

	for( i = 0, y = 0; y < in->ysize; y++ ) {
		for( x = 0; x < in->xsize; x++, i++ ) 
			write_line( fp, "%d ", in->coeff[i] );

		if( write_line( fp, "\n" ) ) {
			fclose( fp ); 
			return( -1 );
		}
	}
	fclose( fp );

	return( 0 );
}

/**
 * im_write_imask:
 * @in: mask to write
 *
 * Write an imask to a file.
 *
 * See also: im_write_imask_name().
 *
 * Returns: 0 on success, or -1 on error.
 */
int 
im_write_imask( INTMASK *in )
{
	if( !in->filename ) { 
		im_error( "im_write_imask", "%s", _( "filename not set" ) );
		return( -1 );
	}

	return( im_write_imask_name( in, in->filename ) );
}

/**
 * im_write_dmask_name:
 * @in: mask to write
 * @filename: filename to write to
 *
 * Write a dmask to a file. See im_read_dmask() for a description of the mask
 * file format.
 *
 * See also: im_write_dmask().
 *
 * Returns: 0 on success, or -1 on error.
 */
int 
im_write_dmask_name( DOUBLEMASK *in, const char *filename )
{
	FILE *fp;
	int x, y, i;

	if( im_check_dmask( "im_write_dmask_name", in ) ||
		!(fp = im__file_open_write( filename, TRUE )) )
		return( -1 );

	if( write_line( fp, "%d %d", in->xsize, in->ysize ) ) {
		fclose( fp ); 
		return( -1 );
	}
	if( in->scale != 1.0 || in->offset != 0.0 ) {
		write_line( fp, " " );
		write_double( fp, in->scale );
		write_line( fp, " " );
		write_double( fp, in->offset );
	}
	write_line( fp, "\n" );

	for( i = 0, y = 0; y < in->ysize; y++ ) {
		for( x = 0; x < in->xsize; x++, i++ ) {
			write_double( fp, in->coeff[i] );
			write_line( fp, " " );
		}

		if( write_line( fp, "\n" ) ) {
			fclose( fp ); 
			return( -1 );
		}
	}
	fclose( fp );

	return( 0 );
}

/**
 * im_write_dmask:
 * @in: mask to write
 *
 * Write a dmask to a file. See im_read_dmask() for a description of the mask
 * file format.
 *
 * See also: im_write_dmask_name().
 *
 * Returns: 0 on success, or -1 on error.
 */
int 
im_write_dmask( DOUBLEMASK *in )
{
	if( !in->filename ) { 
		im_error( "im_write_dmask", "%s", _( "filename not set" ) );
		return( -1 );
	}

	return( im_write_dmask_name( in, in->filename ) );
}

/* Copy an imask into a matrix. Only used internally by matrix package for
 * invert.
 */
void 
im_copy_imask_matrix( INTMASK *mask, int **matrix )
{	
	int x, y;
	int *p = mask->coeff;

	for( y = 0; y < mask->ysize; y++ )
		for( x = 0; x < mask->xsize; x++ )
			matrix[x][y] = *p++;
}


/* Copy a matrix into an imask.
 */
void 
im_copy_matrix_imask( int **matrix, INTMASK *mask )
{	
	int x, y;
	int *p = mask->coeff;

	for( y = 0; y < mask->ysize; y++ )
		for( x = 0; x < mask->xsize; x++ )
			*p++ = matrix[x][y];
}

/* Copy a dmask into a matrix.
 */
void 
im_copy_dmask_matrix( DOUBLEMASK *mask, double **matrix )
{	
	int x, y;
	double *p = mask->coeff;

	for( y = 0; y < mask->ysize; y++ )
		for( x = 0; x < mask->xsize; x++ )
			matrix[x][y] = *p++;
}

/* Copy a matrix to a dmask.
 */
void 
im_copy_matrix_dmask( double **matrix, DOUBLEMASK *mask )
{	
	int x, y;
	double *p = mask->coeff;

	for( y = 0; y < mask->ysize; y++ )
		for( x = 0; x < mask->xsize; x++ )
			*p++ = matrix[x][y];
}

/**
 * im_print_imask:
 * @in: mask to print
 *
 * Print an imask to stdout.
 *
 * See also: im_print_dmask().
 */
void 
im_print_imask( INTMASK *in )
{
        int i, j, k;

        printf( "%s: %d %d %d %d\n",
		in->filename, in->xsize, in->ysize, in->scale, in->offset );

        for( k = 0, j = 0; j < in->ysize; j++ ) {
                for( i = 0; i < in->xsize; i++, k++ )
                        printf( "%d\t", in->coeff[k] );

                printf( "\n" );
	}
}

/**
 * im_print_dmask:
 * @in: mask to print
 *
 * Print a dmask to stdout.
 *
 * See also: im_print_imask().
 */
void 
im_print_dmask( DOUBLEMASK *in )
{
        int i, j, k;

        printf( "%s: %d %d %f %f\n",
		in->filename, in->xsize, in->ysize, in->scale, in->offset );

        for( k = 0, j = 0; j < in->ysize; j++ ) {
                for( i = 0; i < in->xsize; i++, k++ )
                        printf( "%f\t", in->coeff[k] );

                printf( "\n" );
	}
}

/**
 * im_local_dmask:
 * @out: image to make the mask local to
 * @mask: mask to local-ize
 *
 * @out takes ownership of @mask: when @out is closed, @mask will be closed
 * for you. If im_local_dmask() itself fails, the mask is also freed.
 *
 * See also: im_local_imask().
 *
 * Returns: the mask, or NULL on error.
 */
DOUBLEMASK *
im_local_dmask( VipsImage *out, DOUBLEMASK *mask )
{
	if( im_check_dmask( "im_local_dmask", mask ) )
		return( NULL );

	if( im_add_close_callback( out, 
		(im_callback_fn) im_free_dmask, mask, NULL ) ) {
		im_free_dmask( mask );
		return( NULL );
	}

	return( mask );
}

/**
 * im_local_imask:
 * @out: image to make the mask local to
 * @mask: mask to local-ize
 *
 * @out takes ownership of @mask: when @out is closed, @mask will be closed
 * for you. If im_local_imask() itself fails, the mask is also freed.
 *
 * See also: im_local_dmask().
 *
 * Returns: the mask, or NULL on error.
 */
INTMASK *
im_local_imask( VipsImage *out, INTMASK *mask )
{
	if( im_check_imask( "im_local_dmask", mask ) )
		return( NULL );

	if( im_add_close_callback( out, 
		(im_callback_fn) im_free_imask, mask, NULL ) ) {
		im_free_imask( mask );
		return( NULL );
	}

	return( mask );
}
