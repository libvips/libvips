/* Read a ppm file.
 * 

 * 4/2/10
 * 	- gtkdoc

 * 13/11/19
 * 	- redone with streams
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

#ifdef HAVE_PPM

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

struct _Write;

typedef int (*write_fn)( struct _Write *write, VipsPel *p );

/* What we track during a PPM write.
 */
typedef struct _Write {
	VipsImage *in;
	VipsStreamo *streamo;
	write_fn fn;
} Write;

static void
write_destroy( Write *write )
{
	if( write->streamo ) 
		vips_streamo_finish( write->streamo );
	VIPS_UNREF( write->streamo );

	vips_free( write );
}

static Write *
write_new( VipsImage *in, VipsStreamo *streamo )
{
	Write *write;

	if( !(write = VIPS_NEW( NULL, Write )) )
		return( NULL );

	write->in = in;
        write->streamo = streamo;
	g_object_ref( streamo );
        write->fn = NULL;

        return( write );
}

static int
write_ppm_line_ascii( Write *write, VipsPel *p )
{
	const int sk = VIPS_IMAGE_SIZEOF_PEL( write->in );
	int x, k;

	for( x = 0; x < write->in->Xsize; x++ ) {
		for( k = 0; k < write->in->Bands; k++ ) {
			switch( write->in->BandFmt ) {
			case VIPS_FORMAT_UCHAR:
				vips_streamo_writef( write->streamo, 
					"%d ", p[k] );
				break;

			case VIPS_FORMAT_USHORT:
				vips_streamo_writef( write->streamo, 
					"%d ", ((unsigned short *) p)[k] );
				break;

			case VIPS_FORMAT_UINT:
				vips_streamo_writef( write->streamo, 
					"%d ", ((unsigned int *) p)[k] );
				break;

			default:
				g_assert_not_reached();
			}
		}

		p += sk;
	}

	if( vips_streamo_writef( write->streamo, "\n" ) ) 
		return( -1 );

	return( 0 );
}

static int
write_ppm_line_ascii_squash( Write *write, VipsPel *p )
{
	int x;

	for( x = 0; x < write->in->Xsize; x++ ) 
		vips_streamo_writef( write->streamo, "%d ", p[x] ? 0 : 1 );

	if( vips_streamo_writef( write->streamo, "\n" ) ) 
		return( -1 );

	return( 0 );
}

static int
write_ppm_line_binary( Write *write, VipsPel *p )
{
	if( vips_streamo_write( write->streamo, 
		p, VIPS_IMAGE_SIZEOF_LINE( write->in ) ) ) 
		return( -1 );

	return( 0 );
}

static int
write_ppm_line_binary_squash( Write *write, VipsPel *p )
{
	int x;
	int bits;
	int n_bits;

	bits = 0;
	n_bits = 0;
	for( x = 0; x < write->in->Xsize; x++ ) {
		bits = VIPS_LSHIFT_INT( bits, 1 );
		n_bits += 1;
		bits |= p[x] ? 0 : 1;

		if( n_bits == 8 ) {
			if( VIPS_STREAMO_PUTC( write->streamo, bits ) ) 
				return( -1 );

			bits = 0;
			n_bits = 0;
		}
	}

	/* Flush any remaining bits in this line.
	 */
	if( n_bits &&
		VIPS_STREAMO_PUTC( write->streamo, bits ) ) 
		return( -1 );

	return( 0 );
}

static int
write_ppm_block( VipsRegion *region, VipsRect *area, void *a )
{
	Write *write = (Write *) a;
	int i;

	for( i = 0; i < area->height; i++ ) {
		VipsPel *p = VIPS_REGION_ADDR( region, 0, area->top + i );

		if( write->fn( write, p ) )
			return( -1 );
	}

	return( 0 );
}

static int
write_ppm( Write *write, gboolean ascii, gboolean squash ) 
{
	VipsImage *in = write->in;

	char *magic;
	time_t timebuf;

	magic = "unset";
	if( in->BandFmt == VIPS_FORMAT_FLOAT && in->Bands == 3 ) 
		magic = "PF";
	else if( in->BandFmt == VIPS_FORMAT_FLOAT && in->Bands == 1 ) 
		magic = "Pf";
	else if( in->Bands == 1 && ascii && squash )
		magic = "P1";
	else if( in->Bands == 1 && ascii )
		magic = "P2";
	else if( in->Bands == 1 && !ascii && squash )
		magic = "P4";
	else if( in->Bands == 1 && !ascii )
		magic = "P5";
	else if( in->Bands == 3 && ascii )
		magic = "P3";
	else if( in->Bands == 3 && !ascii )
		magic = "P6";
	else
		g_assert_not_reached();

	vips_streamo_writef( write->streamo, "%s\n", magic );
	time( &timebuf );
	vips_streamo_writef( write->streamo, 
		"#vips2ppm - %s\n", ctime( &timebuf ) );
	vips_streamo_writef( write->streamo, "%d %d\n", in->Xsize, in->Ysize );

	if( !squash ) 
		switch( in->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			vips_streamo_writef( write->streamo, 
				"%d\n", UCHAR_MAX );
			break;

		case VIPS_FORMAT_USHORT:
			vips_streamo_writef( write->streamo, 
				"%d\n", USHRT_MAX );
			break;

		case VIPS_FORMAT_UINT:
			vips_streamo_writef( write->streamo, 
				"%d\n", UINT_MAX );
			break;

		case VIPS_FORMAT_FLOAT:
{
			double scale;

			if( vips_image_get_double( in, "pfm-scale", &scale ) )
				scale = 1;
			if( !vips_amiMSBfirst() )
				scale *= -1;
			vips_streamo_writef( write->streamo, 
				"%g\n", scale );
}
			break;

		default:
			g_assert_not_reached();
		}

	if( squash )
		write->fn = ascii ? 
			write_ppm_line_ascii_squash : 
			write_ppm_line_binary_squash;
	else
		write->fn = ascii ? 
			write_ppm_line_ascii : 
			write_ppm_line_binary;

	if( vips_sink_disc( write->in, write_ppm_block, write ) )
		return( -1 );

	return( 0 );
}

int
vips__ppm_save_stream( VipsImage *in, VipsStreamo *streamo,
	gboolean ascii, gboolean squash )
{
	Write *write;

	if( vips_check_uintorf( "vips2ppm", in ) || 
		vips_check_bands_1or3( "vips2ppm", in ) || 
		vips_check_uncoded( "vips2ppm", in ) || 
		vips_image_pio_input( in ) )
		return( -1 );

	if( ascii && 
		in->BandFmt == VIPS_FORMAT_FLOAT ) {
		g_warning( "%s", 
			_( "float images must be binary -- disabling ascii" ) );
		ascii = FALSE;
	}

	/* One bit images must come from a 8 bit, one band source. 
	 */
	if( squash && 
		(in->Bands != 1 || 
		 in->BandFmt != VIPS_FORMAT_UCHAR) ) {
		g_warning( "%s", 
			_( "can only squash 1 band uchar images -- " 
				"disabling squash" ) );
		squash = FALSE; 
	}

	if( !(write = write_new( in, streamo )) )
		return( -1 );

	if( write_ppm( write, ascii, squash ) ) {
		write_destroy( write );
		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}

#endif /*HAVE_PPM*/
