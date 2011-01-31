/* Write a ppm file.
 *
 * 28/11/03 JC
 *	- better no-overshoot on tile loop
 * 9/9/05
 * 	- tiny cleanups
 * 3/11/07
 * 	- use im_wbuffer() for bg writes
 * 4/2/10
 * 	- gtkdoc
 * 	- cleanups
 * 1/5/10
 * 	- add PFM (portable float map) support
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

typedef int (*write_fn)( IMAGE *in, FILE *fp, PEL *p );

/* What we track during a PPM write.
 */
typedef struct {
	IMAGE *in;
	FILE *fp;
	char *name;
	write_fn fn;
} Write;

static void
write_destroy( Write *write )
{
	IM_FREEF( fclose, write->fp );
	IM_FREE( write->name );

	im_free( write );
}

static Write *
write_new( IMAGE *in, const char *name )
{
	Write *write;

	if( !(write = IM_NEW( NULL, Write )) )
		return( NULL );

	write->in = in;
	write->name = im_strdup( NULL, name );
        write->fp = im__file_open_write( name, FALSE );

	if( !write->name || !write->fp ) {
		write_destroy( write );
		return( NULL );
	}
	
        return( write );
}

static int
write_ppm_line_ascii( IMAGE *in, FILE *fp, PEL *p )
{
	const int sk = IM_IMAGE_SIZEOF_PEL( in );
	int x, k;

	for( x = 0; x < in->Xsize; x++ ) {
		for( k = 0; k < in->Bands; k++ ) {
			switch( in->BandFmt ) {
			case IM_BANDFMT_UCHAR:
				fprintf( fp, "%d ", p[k] );
				break;

			case IM_BANDFMT_USHORT:
				fprintf( fp, "%d ", ((unsigned short *) p)[k] );
				break;

			case IM_BANDFMT_UINT:
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
		im_error( "im_vips2ppm", 
			"%s", _( "write error ... disc full?" ) );
		return( -1 );
	}

	return( 0 );
}

static int
write_ppm_line_binary( IMAGE *in, FILE *fp, PEL *p )
{
	if( !fwrite( p, IM_IMAGE_SIZEOF_LINE( in ), 1, fp ) ) {
		im_error( "im_vips2ppm", 
			"%s", _( "write error ... disc full?" ) );
		return( -1 );
	}

	return( 0 );
}

static int
write_ppm_block( REGION *region, Rect *area, void *a )
{
	Write *write = (Write *) a;
	int i;

	for( i = 0; i < area->height; i++ ) {
		PEL *p = (PEL *) IM_REGION_ADDR( region, 0, area->top + i );

		if( write->fn( write->in, write->fp, p ) )
			return( -1 );
	}

	return( 0 );
}

static int
write_ppm( Write *write, int ascii ) 
{
	IMAGE *in = write->in;

	char *magic;
	time_t timebuf;

	if( in->BandFmt == IM_BANDFMT_FLOAT && in->Bands == 3 ) 
		magic = "PF";
	else if( in->BandFmt == IM_BANDFMT_FLOAT && in->Bands == 1 ) 
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
	fprintf( write->fp, "#im_vips2ppm - %s\n", ctime( &timebuf ) );
	fprintf( write->fp, "%d %d\n", in->Xsize, in->Ysize );

	switch( in->BandFmt ) {
	case IM_BANDFMT_UCHAR:
		fprintf( write->fp, "%d\n", UCHAR_MAX );
		break;

	case IM_BANDFMT_USHORT:
		fprintf( write->fp, "%d\n", USHRT_MAX );
		break;

	case IM_BANDFMT_UINT:
		fprintf( write->fp, "%d\n", UINT_MAX );
		break;

	case IM_BANDFMT_FLOAT:
{
		double scale;

		if( im_meta_get_double( in, "pfm-scale", &scale ) )
			scale = 1;
		if( !im_amiMSBfirst() )
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

/**
 * im_vips2ppm:
 * @in: image to save 
 * @filename: file to write to 
 *
 * Write a VIPS image to a file as PPM. It can write 8, 16 or
 * 32 bit unsigned integer images, float images, colour or monochrome, 
 * stored as binary or ASCII. 
 * Integer images of more than 8 bits can only be stored in ASCII.
 *
 * When writing float (PFM) images the scale factor is set from the 
 * "pfm-scale" metadata.
 *
 * The storage format is indicated by a filename extension, for example:
 *
 * |[ 
 * im_vips2ppm( im, "fred.ppm:ascii" )
 * ]|
 *
 * will write to "fred.ppm" in ascii format. The default is binary.
 *
 * See also: #VipsFormat, im_ppm2vips(), im_meta_set_double().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_vips2ppm( IMAGE *in, const char *filename )
{
	Write *write;
	int ascii;
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];

	/* Default to binary output ... much smaller.
	 */
	ascii = 0;

	/* Extract write mode from filename.
	 */
	im_filename_split( filename, name, mode );
	if( strcmp( mode, "" ) != 0 ) {
		if( im_isprefix( "binary", mode ) )
			ascii = 0;
		else if( im_isprefix( "ascii", mode ) )
			ascii = 1;
		else {
			im_error( "im_vips2ppm", 
				"%s", _( "bad mode string, "
					"should be \"binary\" or \"ascii\"" ) );
			return( -1 );
		}
	}

	if( im_check_uintorf( "im_vips2ppm", in ) || 
		im_check_bands_1or3( "im_vips2ppm", in ) || 
		im_check_uncoded( "im_vips2ppm", in ) || 
		im_pincheck( in ) )
		return( -1 );

	/* We can only write >8 bit binary images in float.
	 */
	if( im_bits_of_fmt( in->BandFmt ) > 8 && 
		!ascii && 
		in->BandFmt != IM_BANDFMT_FLOAT ) {
		im_error( "im_vips2ppm", 
			"%s", _( "binary >8 bit images must be float" ) );
		return( -1 );
	}

	if( !(write = write_new( in, name )) )
		return( -1 );

	if( write_ppm( write, ascii ) ) {
		write_destroy( write );
		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}
