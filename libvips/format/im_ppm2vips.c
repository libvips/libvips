/* Read a ppm file.
 * 
 * Stephen Chan ... original code
 *
 * 21/11/00 JC
 *	- hacked for VIPS
 *	- reads ppm/pgm/pbm
 *	- mmaps binary pgm/ppm
 *	- reads all ascii formats (slowly!)
 * 22/11/00 JC
 *	- oops, ascii read was broken
 *	- does 16/32 bit ascii now as well
 * 24/5/01
 *	- im_ppm2vips_header() added
 * 22/5/04
 *	- does 16/32 bit binary too
 *	- tiny fix for missing file close on read error
 * 19/8/05
 * 	- use im_raw2vips() for binary read
 * 9/9/05
 * 	- tiny cleanups
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

#include <ctype.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* The largest number/field/whatever we can read.
 */
#define IM_MAX_THING (80)

static void 
skip_line( FILE *fp )
{
        int ch;

        while( (ch = fgetc( fp )) != '\n' )
		;
}

static void 
skip_white_space( FILE *fp )
{
        int ch;

        while( isspace( ch = fgetc( fp ) ) )
		;
	ungetc( ch, fp );

	if( ch == '#' ) {
		skip_line( fp );
		skip_white_space( fp );
	}
}

static int
read_uint( FILE *fp )
{
	int i;
	char buf[IM_MAX_THING];
	int ch;

	skip_white_space( fp );

	/* Stop complaints about used-before-set on ch.
	 */
	ch = -1;

	for( i = 0; i < IM_MAX_THING - 1 && isdigit( ch = fgetc( fp ) ); i++ ) 
		buf[i] = ch;
	buf[i] = '\0';

	if( i == 0 ) {
		im_error( "im_ppm2vips", "%s", _( "bad unsigned int" ) );
		return( -1 );
	}

	ungetc( ch, fp );

	return( atoi( buf ) );
}

static int
read_header( FILE *fp, IMAGE *out, int *bits, int *ascii )
{
	int width, height, bands, fmt, type;
	int i;
	char buf[IM_MAX_THING];
	int max_value;

	/* ppm types.
	 */
	static char *magic_names[] = {
		"P1",	/* pbm ... 1 band 1 bit, ascii */
		"P2",	/* pgm ... 1 band many bit, ascii */
		"P3",	/* ppm ... 3 band many bit, ascii */
		"P4",	/* pbm ... 1 band 1 bit, binary */
		"P5",	/* pgm ... 1 band 8 bit, binary */
		"P6"	/* ppm ... 3 band 8 bit, binary */
	};

	/* Characteristics, indexed by ppm type.
	 */
	static int lookup_bits[] = {
		1, 8, 8, 1, 8, 8
	};
	static int lookup_bands[] = {
		1, 1, 3, 1, 1, 3
	};
	static int lookup_ascii[] = {
		1, 1, 1, 0, 0, 0
	};

	/* Read in the magic number.
	 */
	buf[0] = fgetc( fp );
	buf[1] = fgetc( fp );
	buf[2] = '\0';

	for( i = 0; i < IM_NUMBER( magic_names ); i++ )
		if( strcmp( magic_names[i], buf ) == 0 ) 
			break;
	if( i == IM_NUMBER( magic_names ) ) {
		im_error( "im_ppm2vips", "%s", _( "bad magic number" ) );
		return( -1 );
	}
	*bits = lookup_bits[i];
	bands = lookup_bands[i];
	*ascii = lookup_ascii[i];

	/* Read in size.
	 */
	if( (width = read_uint( fp )) < 0 ||
		(height = read_uint( fp )) < 0 )
		return( -1 );

	/* Read in max value for >1 bit images.
	 */
	if( *bits > 1 ) {
		if( (max_value = read_uint( fp )) < 0 )
			return( -1 );

		if( max_value > 255 )
			*bits = 16;
		if( max_value > 65535 )
			*bits = 32;
	}

	/* For binary images, there is always exactly 1 more whitespace
	 * character before the data starts.
	 */
	if( !*ascii && !isspace( fgetc( fp ) ) ) {
		im_error( "im_ppm2vips", "%s", 
			_( "not whitespace before start of binary data" ) );
		return( -1 );
	}

	/* Choose a VIPS bandfmt.
	 */
	switch( *bits ) {
	case 1:
	case 8:
		fmt = IM_BANDFMT_UCHAR;
		break;

	case 16:
		fmt = IM_BANDFMT_USHORT;
		break;

	case 32:
		fmt = IM_BANDFMT_UINT;
		break;

	default:
		assert( 0 );
	}

	if( bands == 1 ) {
		if( fmt == IM_BANDFMT_USHORT )
			type = IM_TYPE_GREY16;
		else
			type = IM_TYPE_B_W;
	}
	else {
		if( fmt == IM_BANDFMT_USHORT )
			type = IM_TYPE_RGB16;
		else if( fmt == IM_BANDFMT_UINT )
			type = IM_TYPE_RGB;
		else 
			type = IM_TYPE_sRGB;
	}

	im_initdesc( out, width, height, bands, (*bits == 1) ? 8 : *bits, fmt, 
		IM_CODING_NONE, 
		type,
		1.0, 1.0,
		0, 0 );

	return( 0 );
}

/* Read a ppm/pgm file using mmap().
 */
static int
read_mmap( FILE *fp, const char *filename, IMAGE *out )
{
	const int header_offset = ftell( fp );
	IMAGE *t[2];

	if( im_open_local_array( out, t, 2, "im_ppm2vips", "p" ) ||
		im_raw2vips( filename, t[0], 
			out->Xsize, out->Ysize, 
			IM_IMAGE_SIZEOF_PEL( out ), header_offset ) ||
		im_copy_morph( t[0], t[1],
			out->Bands, out->BandFmt, out->Coding ) ||
		im_copy_native( t[1], out, TRUE ) ) 
		return( -1 );

	return( 0 );
}

/* Read an ascii ppm/pgm file.
 */
static int
read_ascii( FILE *fp, IMAGE *out )
{
	int x, y;
	PEL *buf;

	if( im_outcheck( out ) || im_setupout( out ) ||
		!(buf = IM_ARRAY( out, IM_IMAGE_SIZEOF_LINE( out ), PEL )) )
		return( -1 );

	for( y = 0; y < out->Ysize; y++ ) {
		for( x = 0; x < out->Xsize * out->Bands; x++ ) {
			int val;

			if( (val = read_uint( fp )) < 0 )
				return( -1 );
			
			switch( out->BandFmt ) {
			case IM_BANDFMT_UCHAR:
				buf[x] = IM_CLIP( 0, val, 255 );
				break;

			case IM_BANDFMT_USHORT:
				((unsigned short *) buf)[x] = 
					IM_CLIP( 0, val, 65535 );
				break;

			case IM_BANDFMT_UINT:
				((unsigned int *) buf)[x] = val;
				break;

			default:
				assert( 0 );
			}
		}

		if( im_writeline( y, out, buf ) )
			return( -1 );
	}

	return( 0 );
}

/* Read an ascii 1 bit file.
 */
static int
read_1bit_ascii( FILE *fp, IMAGE *out )
{
	int x, y;
	PEL *buf;

	if( im_outcheck( out ) || im_setupout( out ) ||
		!(buf = IM_ARRAY( out, IM_IMAGE_SIZEOF_LINE( out ), PEL )) )
		return( -1 );

	for( y = 0; y < out->Ysize; y++ ) {
		for( x = 0; x < out->Xsize * out->Bands; x++ ) {
			int val;

			if( (val = read_uint( fp )) < 0 )
				return( -1 );

			if( val == 1 )
				buf[x] = 0;
			else
				buf[x] = 255;
		}

		if( im_writeline( y, out, buf ) )
			return( -1 );
	}

	return( 0 );
}

/* Read a 1 bit binary file.
 */
static int
read_1bit_binary( FILE *fp, IMAGE *out )
{
	int x, y, i;
	int bits;
	PEL *buf;

	if( im_outcheck( out ) || im_setupout( out ) ||
		!(buf = IM_ARRAY( out, IM_IMAGE_SIZEOF_LINE( out ), PEL )) )
		return( -1 );

	bits = fgetc( fp );
	for( i = 0, y = 0; y < out->Ysize; y++ ) {
		for( x = 0; x < out->Xsize * out->Bands; x++, i++ ) {
			buf[x] = (bits & 128) ? 255 : 0;
			bits <<= 1;
			if( (i & 7) == 7 )
				bits = fgetc( fp );
		}

		if( im_writeline( y, out, buf ) )
			return( -1 );
	}

	return( 0 );
}

static int 
parse_ppm( FILE *fp, const char *filename, IMAGE *out )
{
	int bits;
	int ascii;

	if( read_header( fp, out, &bits, &ascii ) )
		return( -1 );

	/* What sort of read are we doing?
	 */
	if( !ascii && bits >= 8 )
		return( read_mmap( fp, filename, out ) );
	else if( !ascii && bits == 1 )
		return( read_1bit_binary( fp, out ) );
	else if( ascii && bits == 1 )
		return( read_1bit_ascii( fp, out ) );
	else 
		return( read_ascii( fp, out ) );
}

static int
ppm2vips_header( const char *filename, IMAGE *out )
{
        FILE *fp;
	int bits;
	int ascii;

	if( !(fp = im__file_open_read( filename )) ) 
                return( -1 );
	if( read_header( fp, out, &bits, &ascii ) ) {
		fclose( fp );
		return( -1 );
	}

	fclose( fp );

	return( 0 );
}

/* Can this PPM file be read with a mmap?
 */
static int
isppmmmap( const char *filename )
{
	IMAGE *im;
        FILE *fp;
	int bits;
	int ascii;

	if( !(fp = im__file_open_read( filename )) ) 
                return( -1 );

	if( !(im = im_open( "temp", "p" )) ) {
		fclose( fp );
		return( 0 );
	}
	if( read_header( fp, im, &bits, &ascii ) ) {
		im_close( im );
		fclose( fp );
		return( 0 );
	}
	im_close( im );
	fclose( fp );

	return( !ascii && bits >= 8 );
}

int
im_ppm2vips( const char *filename, IMAGE *out )
{
        FILE *fp;

	if( !(fp = im__file_open_read( filename )) ) 
                return( -1 );
	if( parse_ppm( fp, filename, out ) ) {
		fclose( fp );
		return( -1 );
	}
	fclose( fp );

	return( 0 );
}

static int
isppm( const char *filename )
{
	unsigned char buf[2];

	if( im__get_bytes( filename, buf, 2 ) )
		if( buf[0] == 'P' && (buf[1] >= '1' || buf[1] <= '6') )
			return( 1 );

	return( 0 );
}

/* ppm flags function.
 */
static VipsFormatFlags
ppm_flags( const char *filename )
{
	VipsFormatFlags flags;

	flags = 0;
	if( isppmmmap( filename ) )
		flags |= VIPS_FORMAT_PARTIAL;

	return( flags );
}

static const char *ppm_suffs[] = { ".ppm", ".pgm", ".pbm", NULL };

/* ppm format adds no new members.
 */
typedef VipsFormat VipsFormatPpm;
typedef VipsFormatClass VipsFormatPpmClass;

static void
vips_format_ppm_class_init( VipsFormatPpmClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "ppm";
	object_class->description = _( "PPM/PBM/PNM" );

	format_class->is_a = isppm;
	format_class->header = ppm2vips_header;
	format_class->load = im_ppm2vips;
	format_class->save = im_vips2ppm;
	format_class->get_flags = ppm_flags;
	format_class->suffs = ppm_suffs;
}

static void
vips_format_ppm_init( VipsFormatPpm *object )
{
}

G_DEFINE_TYPE( VipsFormatPpm, vips_format_ppm, VIPS_TYPE_FORMAT );

