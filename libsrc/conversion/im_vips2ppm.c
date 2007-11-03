/* Write a ppm file.
 *
 * 28/11/03 JC
 *	- better no-overshoot on tile loop
 * 9/9/05
 * 	- tiny cleanups
 * 3/11/07
 * 	- use im_wbuffer() for bg writes
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* What we track during a PPM write.
 */
typedef struct {
	IMAGE *in;
	im_threadgroup_t *tg;
	FILE *fp;
	char *name;
} Write;

static void
write_destroy( Write *write )
{
	IM_FREEF( im_threadgroup_free, write->tg );
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
	write->tg = im_threadgroup_create( write->in );
	write->name = im_strdup( NULL, name );

#ifdef BINARY_OPEN
	if( !(write->fp = fopen( name, "wb" )) ) {
#else /*BINARY_OPEN*/
	if( !(write->fp = fopen( name, "w" )) ) {
#endif /*BINARY_OPEN*/
                im_error( "im_vips2ppm", 
			_( "unable to open \"%s\" for output" ), name );
        }

	if( !write->tg || !write->name || !write->fp ) {
		write_destroy( write );
		return( NULL );
	}
	
        return( write );
}

typedef int (*write_fn)( IMAGE *in, FILE *fp, PEL *p );

static int
write_ppm_line_ascii( IMAGE *in, FILE *fp, PEL *p )
{
	const int sk = IM_IMAGE_SIZEOF_PEL( in );
	const int nb = IM_MIN( 3, in->Bands );
	int x, k;

	/* If IM_CODING_LABQ, write 3 bands.
	 */

	for( x = 0; x < in->Xsize; x++ ) {
		for( k = 0; k < nb; k++ ) {
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
				assert( 0 );
			}
		}

		fprintf( fp, " " );

		p += sk;
	}

	if( !fprintf( fp, "\n" ) ) {
		im_error( "im_vips2ppm", _( "write error ... disc full?" ) );
		return( -1 );
	}

	return( 0 );
}

static int
write_ppm_line_binary( IMAGE *in, FILE *fp, PEL *p )
{
	const int sk = IM_IMAGE_SIZEOF_PEL( in );
	const int nb = IM_MIN( 3, in->Bands );
	int x;

	for( x = 0; x < in->Xsize; x++ ) {
		if( !fwrite( p, 1, nb, fp ) ) {
			im_error( "im_vips2ppm", 
				_( "write error ... disc full?" ) );
			return( -1 );
		}

		p += sk;
	}

	return( 0 );
}

static int
write_ppm_block( REGION *region, Rect *area, void *a, void *b )
{
	Write *write = (Write *) a;
	write_fn fn = (write_fn) b;
	int i;

	for( i = 0; i < area->height; i++ ) {
		PEL *p = (PEL *) IM_REGION_ADDR( region, 0, area->top + i );

		if( fn( write->in, write->fp, p ) )
			return( -1 );
	}

	return( 0 );
}

static int
write_ppm( Write *write, int ascii ) 
{
	IMAGE *in = write->in;
	write_fn fn = ascii ? write_ppm_line_ascii : write_ppm_line_binary;

	int max_value;
	char *magic;
	time_t timebuf;

	switch( in->BandFmt ) {
	case IM_BANDFMT_UCHAR:
		max_value = UCHAR_MAX;
		break;

	case IM_BANDFMT_USHORT:
		max_value = USHRT_MAX;
		break;

	case IM_BANDFMT_UINT:
		max_value = UINT_MAX;
		break;

	default:
		assert( 0 );
	}

	if( in->Bands == 1 && ascii )
		magic = "P2";
	else if( in->Bands == 1 && !ascii )
		magic = "P5";
	else if( (in->Bands == 3 || in->Bands == 4) && ascii )
		magic = "P3";
	else if( (in->Bands == 3 || in->Bands == 4) && !ascii )
		magic = "P6";
	else
		assert( 0 );

	fprintf( write->fp, "%s\n", magic );
	time( &timebuf );
	fprintf( write->fp, "#im_vips2ppm - %s\n", ctime( &timebuf ) );
	fprintf( write->fp, "%d %d\n", in->Xsize, in->Ysize );
	fprintf( write->fp, "%d\n", max_value );

	if( im_wbuffer( write->tg, write_ppm_block, write, fn ) )
		return( -1 );

	return( 0 );
}

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
				_( "bad mode string, "
					"should be \"binary\" or \"ascii\"" ) );
			return( -1 );
		}
	}

	if( in->Bbits > 8 && !ascii ) {
		im_error( "im_vips2ppm", 
			_( "can't write binary >8 bit images" ) );
		return( -1 );
	}
	if( !im_isuint( in ) ) {
		im_error( "im_vips2ppm", _( "unsigned int formats only" ) );
		return( -1 );
	}
	if( in->Coding != IM_CODING_NONE && in->Coding != IM_CODING_LABQ ) {
		im_error( "im_vips2ppm", 
			_( "uncoded or IM_CODING_LABQ only" ) );
		return( -1 );
	}
	if( in->Coding == IM_CODING_NONE && in->Bands != 1 && in->Bands != 3 ) {
		im_error( "im_vips2ppm", _( "1 or 3 band images only" ) );
		return( -1 );
	}

	if( im_pincheck( in ) || !(write = write_new( in, name )) )
		return( -1 );

	if( write_ppm( write, ascii ) ) {
		write_destroy( write );
		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}
