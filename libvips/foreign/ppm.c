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
 * 28/11/03 JC
 *	- better no-overshoot on tile loop
 * 22/5/04
 *	- does 16/32 bit binary too
 *	- tiny fix for missing file close on read error
 * 19/8/05
 * 	- use im_raw2vips() for binary read
 * 9/9/05
 * 	- tiny cleanups
 * 3/11/07
 * 	- use im_wbuffer() for bg writes
 * 4/2/10
 * 	- gtkdoc
 * 1/5/10
 * 	- add PFM (portable float map) support
 * 19/12/11
 * 	- rework as a set of fns ready to be called from a class
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "ppm.h"

/* The largest number/field/whatever we can read.
 */
#define MAX_THING (80)

static void 
skip_line( FILE *fp )
{
        while( fgetc( fp ) != '\n' )
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
read_int( FILE *fp, int *i )
{
	skip_white_space( fp );
	if( fscanf( fp, "%d", i ) != 1 ) {
		vips_error( "ppm2vips", "%s", _( "bad int" ) );
		return( -1 );
	}

	return( 0 );
}

static int
read_float( FILE *fp, float *f )
{
	skip_white_space( fp );
	if( fscanf( fp, "%f", f ) != 1 ) {
		vips_error( "ppm2vips", "%s", _( "bad float" ) );
		return( -1 );
	}

	return( 0 );
}

/* ppm types.
 */
static char *magic_names[] = {
	"P1",	/* pbm ... 1 band 1 bit, ascii */
	"P2",	/* pgm ... 1 band many bit, ascii */
	"P3",	/* ppm ... 3 band many bit, ascii */
	"P4",	/* pbm ... 1 band 1 bit, binary */
	"P5",	/* pgm ... 1 band 8 bit, binary */
	"P6",	/* ppm ... 3 band 8 bit, binary */
	"PF",	/* pfm ... 3 band 32 bit, binary */
	"Pf"	/* pfm ... 1 band 32 bit, binary */
};

static int
read_header( FILE *fp, VipsImage *out, int *bits, int *ascii, int *msb_first )
{
	int width, height, bands; 
	VipsBandFormat format;
	VipsInterpretation interpretation; 
	int index;
	char buf[MAX_THING];

	/* Characteristics, indexed by ppm type.
	 */
	static int lookup_bits[] = {
		1, 8, 8, 1, 8, 8, 32, 32
	};
	static int lookup_bands[] = {
		1, 1, 3, 1, 1, 3, 3, 1
	};
	static int lookup_ascii[] = {
		1, 1, 1, 0, 0, 0, 0, 0
	};

	/* Read in the magic number.
	 */
	buf[0] = fgetc( fp );
	buf[1] = fgetc( fp );
	buf[2] = '\0';

	for( index = 0; index < VIPS_NUMBER( magic_names ); index++ )
		if( strcmp( magic_names[index], buf ) == 0 ) 
			break;
	if( index == VIPS_NUMBER( magic_names ) ) {
		vips_error( "ppm2vips", "%s", _( "bad magic number" ) );
		return( -1 );
	}
	*bits = lookup_bits[index];
	bands = lookup_bands[index];
	*ascii = lookup_ascii[index];

	/* Default ... can be changed below for PFM images.
	 */
	*msb_first = 0;

	/* Read in size.
	 */
	if( read_int( fp, &width ) ||
		read_int( fp, &height ) )
		return( -1 );

	/* Read in max value / scale for >1 bit images.
	 */
	if( *bits > 1 ) {
		if( index == 6 || index == 7 ) {
			float scale;

			if( read_float( fp, &scale ) )
				return( -1 );

			/* Scale > 0 means big-endian.
			 */
			*msb_first = scale > 0;
			vips_image_set_double( out, 
				"pfm-scale", fabs( scale ) );
		}
		else {
			int max_value;

			if( read_int( fp, &max_value ) )
				return( -1 );

			if( max_value > 255 )
				*bits = 16;
			if( max_value > 65535 )
				*bits = 32;
		}
	}

	/* For binary images, there is always exactly 1 more whitespace
	 * character before the data starts.
	 */
	if( !*ascii && !isspace( fgetc( fp ) ) ) {
		vips_error( "ppm2vips", "%s", 
			_( "not whitespace before start of binary data" ) );
		return( -1 );
	}

	/* Choose a VIPS bandfmt.
	 */
	switch( *bits ) {
	case 1:
	case 8:
		format = VIPS_FORMAT_UCHAR;
		break;

	case 16:
		format = VIPS_FORMAT_USHORT;
		break;

	case 32:
		if( index == 6 || index == 7 )
			format = VIPS_FORMAT_FLOAT;
		else
			format = VIPS_FORMAT_UINT;
		break;

	default:
		g_assert( 0 );

		/* Keep -Wall happy.
		 */
		return( 0 );
	}

	if( bands == 1 ) {
		if( format == VIPS_FORMAT_USHORT )
			interpretation = VIPS_INTERPRETATION_GREY16;
		else
			interpretation = VIPS_INTERPRETATION_B_W;
	}
	else {
		if( format == VIPS_FORMAT_USHORT )
			interpretation = VIPS_INTERPRETATION_RGB16;
		else if( format == VIPS_FORMAT_UINT )
			interpretation = VIPS_INTERPRETATION_RGB;
		else 
			interpretation = VIPS_INTERPRETATION_sRGB;
	}

	vips_image_init_fields( out,
		width, height, bands, format, 
		VIPS_CODING_NONE, interpretation, 1.0, 1.0 );

	return( 0 );
}

/* Read a ppm/pgm file using mmap().
 */
static int
read_mmap( FILE *fp, const char *filename, int msb_first, VipsImage *out )
{
	const guint64 header_offset = ftell( fp );
	VipsImage *x = vips_image_new();
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( x ), 3 );

	if( vips_rawload( filename, &t[0], 
			out->Xsize, out->Ysize, VIPS_IMAGE_SIZEOF_PEL( out ), 
			"offset", header_offset,
			NULL ) ||
		vips_copy( t[0], &t[1],
			"bands", out->Bands, 
			"format", out->BandFmt, 
			"coding", out->Coding, 
			NULL ) ||
		vips_copy( t[1], &t[2], 
			"swap", !vips_amiMSBfirst(), 
			NULL ) ||
		vips_image_write( t[2], out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

/* Read an ascii ppm/pgm file.
 */
static int
read_ascii( FILE *fp, VipsImage *out )
{
	int x, y;
	VipsPel *buf;

	if( !(buf = VIPS_ARRAY( out, VIPS_IMAGE_SIZEOF_LINE( out ), VipsPel )) )
		return( -1 );

	for( y = 0; y < out->Ysize; y++ ) {
		for( x = 0; x < out->Xsize * out->Bands; x++ ) {
			int val;

			if( read_int( fp, &val ) )
				return( -1 );
			
			switch( out->BandFmt ) {
			case VIPS_FORMAT_UCHAR:
				buf[x] = VIPS_CLIP( 0, val, 255 );
				break;

			case VIPS_FORMAT_USHORT:
				((unsigned short *) buf)[x] = 
					VIPS_CLIP( 0, val, 65535 );
				break;

			case VIPS_FORMAT_UINT:
				((unsigned int *) buf)[x] = val;
				break;

			default:
				g_assert( 0 );
			}
		}

		if( vips_image_write_line( out, y, buf ) )
			return( -1 );
	}

	return( 0 );
}

/* Read an ascii 1 bit file.
 */
static int
read_1bit_ascii( FILE *fp, VipsImage *out )
{
	int x, y;
	VipsPel *buf;

	if( !(buf = VIPS_ARRAY( out, VIPS_IMAGE_SIZEOF_LINE( out ), VipsPel )) )
		return( -1 );

	for( y = 0; y < out->Ysize; y++ ) {
		for( x = 0; x < out->Xsize * out->Bands; x++ ) {
			int val;

			if( read_int( fp, &val ) )
				return( -1 );

			if( val == 1 )
				buf[x] = 0;
			else
				buf[x] = 255;
		}

		if( vips_image_write_line( out, y, buf ) )
			return( -1 );
	}

	return( 0 );
}

/* Read a 1 bit binary file.
 */
static int
read_1bit_binary( FILE *fp, VipsImage *out )
{
	int x, y, i;
	int bits;
	VipsPel *buf;

	if( !(buf = VIPS_ARRAY( out, VIPS_IMAGE_SIZEOF_LINE( out ), VipsPel )) )
		return( -1 );

	bits = fgetc( fp );
	for( i = 0, y = 0; y < out->Ysize; y++ ) {
		for( x = 0; x < out->Xsize * out->Bands; x++, i++ ) {
			buf[x] = (bits & 128) ? 255 : 0;
			bits <<= 1;
			if( (i & 7) == 7 )
				bits = fgetc( fp );
		}

		if( vips_image_write_line( out, y, buf ) )
			return( -1 );
	}

	return( 0 );
}

static int 
parse_ppm( FILE *fp, const char *filename, VipsImage *out )
{
	int bits;
	int ascii;
	int msb_first;

	if( read_header( fp, out, &bits, &ascii, &msb_first ) )
		return( -1 );

	/* What sort of read are we doing?
	 */
	if( !ascii && bits >= 8 )
		return( read_mmap( fp, filename, msb_first, out ) );
	else if( !ascii && bits == 1 )
		return( read_1bit_binary( fp, out ) );
	else if( ascii && bits == 1 )
		return( read_1bit_ascii( fp, out ) );
	else 
		return( read_ascii( fp, out ) );
}

int
vips__ppm_header( const char *filename, VipsImage *out )
{
        FILE *fp;
	int bits;
	int ascii;
	int msb_first;

	if( !(fp = vips__file_open_read( filename, NULL, FALSE )) ) 
                return( -1 );

	if( read_header( fp, out, &bits, &ascii, &msb_first ) ) {
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
	VipsImage *im;
        FILE *fp;
	int bits;
	int ascii;
	int msb_first;

	if( !(fp = vips__file_open_read( filename, NULL, FALSE )) ) 
                return( -1 );

	im = vips_image_new(); 
	if( read_header( fp, im, &bits, &ascii, &msb_first ) ) {
		g_object_unref( im );
		fclose( fp );

		return( 0 );
	}
	g_object_unref( im );
	fclose( fp );

	return( !ascii && bits >= 8 );
}

int
vips__ppm_load( const char *filename, VipsImage *out )
{
        FILE *fp;

	/* Note that we open in binary mode. If this is a binary PPM, we need
	 * to be able to mmap it.
	 */
	if( !(fp = vips__file_open_read( filename, NULL, FALSE )) ) 
                return( -1 );

	if( parse_ppm( fp, filename, out ) ) {
		fclose( fp );
		return( -1 );
	}

	fclose( fp );

	return( 0 );
}

int
vips__ppm_isppm( const char *filename )
{
	VipsPel buf[3];

	if( vips__get_bytes( filename, buf, 2 ) ) {
		int i;

		buf[2] = '\0';
		for( i = 0; i < VIPS_NUMBER( magic_names ); i++ )
			if( strcmp( (char *) buf, magic_names[i] ) == 0 )
				return( TRUE );
	}

	return( 0 );
}

/* ppm flags function.
 */
VipsForeignFlags
vips__ppm_flags( const char *filename )
{
	VipsForeignFlags flags;

	flags = 0;
	if( isppmmmap( filename ) )
		flags |= VIPS_FOREIGN_PARTIAL;

	return( flags );
}

const char *vips__ppm_suffs[] = { ".ppm", ".pgm", ".pbm", ".pfm", NULL };

typedef int (*write_fn)( VipsImage *in, FILE *fp, VipsPel *p );

/* What we track during a PPM write.
 */
typedef struct {
	VipsImage *in;
	FILE *fp;
	char *name;
	write_fn fn;
} Write;

static void
write_destroy( Write *write )
{
	VIPS_FREEF( fclose, write->fp );
	VIPS_FREE( write->name );

	vips_free( write );
}

static Write *
write_new( VipsImage *in, const char *name )
{
	Write *write;

	if( !(write = VIPS_NEW( NULL, Write )) )
		return( NULL );

	write->in = in;
	write->name = vips_strdup( NULL, name );
        write->fp = vips__file_open_write( name, FALSE );

	if( !write->name || !write->fp ) {
		write_destroy( write );
		return( NULL );
	}
	
        return( write );
}

static int
write_ppm_line_ascii( VipsImage *in, FILE *fp, VipsPel *p )
{
	const int sk = VIPS_IMAGE_SIZEOF_PEL( in );
	int x, k;

	for( x = 0; x < in->Xsize; x++ ) {
		for( k = 0; k < in->Bands; k++ ) {
			switch( in->BandFmt ) {
			case VIPS_FORMAT_UCHAR:
				fprintf( fp, "%d ", p[k] );
				break;

			case VIPS_FORMAT_USHORT:
				fprintf( fp, "%d ", ((unsigned short *) p)[k] );
				break;

			case VIPS_FORMAT_UINT:
				fprintf( fp, "%d ", ((unsigned int *) p)[k] );
				break;

			default:
				g_assert( 0 );
			}
		}

		fprintf( fp, " " );

		p += sk;
	}

	if( !fprintf( fp, "\n" ) ) {
		vips_error( "vips2ppm", 
			"%s", _( "write error ... disc full?" ) );
		return( -1 );
	}

	return( 0 );
}

static int
write_ppm_line_binary( VipsImage *in, FILE *fp, VipsPel *p )
{
	if( !fwrite( p, VIPS_IMAGE_SIZEOF_LINE( in ), 1, fp ) ) {
		vips_error( "vips2ppm", 
			"%s", _( "write error ... disc full?" ) );
		return( -1 );
	}

	return( 0 );
}

static int
write_ppm_block( VipsRegion *region, VipsRect *area, void *a )
{
	Write *write = (Write *) a;
	int i;

	for( i = 0; i < area->height; i++ ) {
		VipsPel *p = VIPS_REGION_ADDR( region, 0, area->top + i );

		if( write->fn( write->in, write->fp, p ) )
			return( -1 );
	}

	return( 0 );
}

static int
write_ppm( Write *write, int ascii ) 
{
	VipsImage *in = write->in;

	char *magic;
	time_t timebuf;

	magic = "unset";
	if( in->BandFmt == VIPS_FORMAT_FLOAT && in->Bands == 3 ) 
		magic = "PF";
	else if( in->BandFmt == VIPS_FORMAT_FLOAT && in->Bands == 1 ) 
		magic = "Pf";
	else if( in->Bands == 1 && ascii )
		magic = "P2";
	else if( in->Bands == 1 && !ascii )
		magic = "P5";
	else if( in->Bands == 3 && ascii )
		magic = "P3";
	else if( in->Bands == 3 && !ascii )
		magic = "P6";
	else
		g_assert( 0 );

	fprintf( write->fp, "%s\n", magic );
	time( &timebuf );
	fprintf( write->fp, "#vips2ppm - %s\n", ctime( &timebuf ) );
	fprintf( write->fp, "%d %d\n", in->Xsize, in->Ysize );

	switch( in->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		fprintf( write->fp, "%d\n", UCHAR_MAX );
		break;

	case VIPS_FORMAT_USHORT:
		fprintf( write->fp, "%d\n", USHRT_MAX );
		break;

	case VIPS_FORMAT_UINT:
		fprintf( write->fp, "%d\n", UINT_MAX );
		break;

	case VIPS_FORMAT_FLOAT:
{
		double scale;

		if( vips_image_get_double( in, "pfm-scale", &scale ) )
			scale = 1;
		if( !vips_amiMSBfirst() )
			scale *= -1;
		fprintf( write->fp, "%g\n", scale );
}
		break;

	default:
		g_assert( 0 );
	}

	write->fn = ascii ? write_ppm_line_ascii : write_ppm_line_binary;

	if( vips_sink_disc( write->in, write_ppm_block, write ) )
		return( -1 );

	return( 0 );
}

int
vips__ppm_save( VipsImage *in, const char *filename, gboolean ascii )
{
	Write *write;

	if( vips_check_uintorf( "vips2ppm", in ) || 
		vips_check_bands_1or3( "vips2ppm", in ) || 
		vips_check_uncoded( "vips2ppm", in ) || 
		vips_image_pio_input( in ) )
		return( -1 );

	/* We can only write >8 bit binary images in float.
	 */
	if( vips_format_sizeof( in->BandFmt ) > 1 && 
		!ascii && 
		in->BandFmt != VIPS_FORMAT_FLOAT ) {
		vips_error( "vips2ppm", 
			"%s", _( "binary >8 bit images must be float" ) );
		return( -1 );
	}

	if( !(write = write_new( in, filename )) )
		return( -1 );

	if( write_ppm( write, ascii ) ) {
		write_destroy( write );
		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}
