/* Read Radiance (.hdr) files 
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

/*

    Sections of this reader come from Greg Ward and Radiance with kind 
    permission. The Radience copyright notice appears in "copyright.h".

 */

/*
 */
#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "rtio.h"
#include "resolu.h"
#include "color.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* What we track during an radiance-file read.
 */
typedef struct {
	char *filename;
	IMAGE *out;

	FILE *fin;
	char format[256];
	double expos;
	COLOR colcor;
	double aspect;
	RGBPRIMS prims;

	COLOR *buf;
} Read;

static int
israd( const char *filename )
{
	FILE *fin;
	char format[256];
	int result;

#ifdef DEBUG
	printf( "israd: \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(fin = fopen( filename, "r" )) )
		return( 0 );
	strcpy( format, "*" );
	result = checkheader( fin, format, NULL );
	fclose( fin );

	return( result );
}

static void
read_destroy( Read *read )
{
	IM_FREE( read->filename );
	IM_FREEF( fclose, read->fin );
	IM_FREE( read->buf );

	im_free( read );
}

static Read *
read_new( const char *filename, IMAGE *out )
{
	Read *read;
	int i;

	if( !(read = IM_NEW( NULL, Read )) )
		return( NULL );

	read->filename = im_strdup( NULL, filename );
	read->out = out;
	read->fin = NULL;
	strcpy( read->format, COLRFMT );
	read->expos = 1.0;
	for( i = 0; i < 3; i++ )
		read->colcor[i] = 1.0;
	read->aspect = 1.0;
	read->prims[0][0] = CIE_x_r;
	read->prims[0][1] = CIE_y_r;
	read->prims[1][0] = CIE_x_g;
	read->prims[1][1] = CIE_y_g;
	read->prims[2][0] = CIE_x_b;
	read->prims[2][1] = CIE_y_b;
	read->prims[3][0] = CIE_x_w;
	read->prims[3][1] = CIE_y_w;
	read->buf = NULL;

	if( !(read->fin = fopen( filename, "r" )) ) {
		read_destroy( read );
		return( NULL );
	}

	return( read );
}

static int
rad2vips_process_line( char *line, Read *read )
{
	if( isformat( line ) ) {
		if( formatval( line, read->format ) )
			return( -1 );
	}
	else if( isexpos( line ) ) {
		read->expos *= exposval( line );
	}
	else if( iscolcor( line ) ) {
		COLOR cc;
		int i;

		colcorval( cc, line );
		for( i = 0; i < 3; i++ )
			read->colcor[i] *= cc[i];
	}
	else if( isaspect( line ) ) {
		read->aspect *= aspectval( line );
	}
	else if( isprims( line ) ) {
		primsval( read->prims, line );
	}

	return( 0 );
}

static const char *prims_name[4][2] = {
	{ "rad-prims-rx", "rad-prims-ry" }, 
	{ "rad-prims-gx", "rad-prims-gy" },
	{ "rad-prims-bx", "rad-prims-by" },
	{ "rad-prims-wx", "rad-prims-wy" }
};

static const char *colcor_name[3] = {
	"rad-colcor-r",
	"rad-colcor-g",
	"rad-colcor-b"
};

static int
rad2vips_get_header( Read *read, FILE *fin, IMAGE *out )
{
	RESOLU rs;
	int i, j;

	if( getheader( fin, (gethfunc *) rad2vips_process_line, read ) ||
		!fgetsresolu( &rs, fin ) ) {
		im_error( "rad2vips", 
			"%s", _( "error reading radiance header" ) );
		return( -1 );
	}
	out->Xsize = scanlen( &rs );
	out->Ysize = numscans( &rs );

	out->Bands = 3;
	out->BandFmt = IM_BANDFMT_FLOAT;
	out->Bbits = im_bits_of_fmt( out->BandFmt );

	out->Coding = IM_CODING_NONE;
	out->Xres = 1.0;
	out->Yres = read->aspect;
	out->Xoffset = 0.0;
	out->Yoffset = 0.0;

	if( im_meta_set_string( out, "rad-format", read->format ) )
		return( -1 );

	if( strcmp( read->format, COLRFMT ) == 0 )
		out->Type = IM_TYPE_RGB;
	else if( strcmp( read->format, CIEFMT ) == 0 )
		out->Type = IM_TYPE_XYZ;
	else
		out->Type = IM_TYPE_MULTIBAND;

	if( im_meta_set_double( out, "rad-expos", read->expos ) )
		return( -1 );

	for( i = 0; i < 3; i++ )
		if( im_meta_set_double( out, colcor_name[i], read->colcor[i] ) )
			return( -1 );

	if( im_meta_set_double( out, "rad-aspect", read->aspect ) )
		return( -1 );

	for( i = 0; i < 4; i++ )
		for( j = 0; j < 2; j++ )
			if( im_meta_set_double( out, 
				prims_name[i][j], read->prims[i][j] ) )
				return( -1 );

	return( 0 );
}

static int
rad2vips_header( const char *filename, IMAGE *out )
{
	Read *read;

#ifdef DEBUG
	printf( "rad2vips_header: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) ) 
		return( -1 );
	if( rad2vips_get_header( read, read->fin, read->out ) ) {
		read_destroy( read );
		return( -1 );
	}
	read_destroy( read );

	return( 0 );
}

static int
rad2vips_get_data( Read *read, FILE *fin, IMAGE *im )
{
	int y;

#ifdef DEBUG
	printf( "rad2vips_get_data\n" );
#endif /*DEBUG*/

	if( im_outcheck( im ) ||
		im_setupout( im ) )
		return( -1 );
	if( !(read->buf = IM_ARRAY( NULL, im->Xsize, COLOR )) )
		return( -1 );

	for( y = 0; y < im->Ysize; y++ ) {
		if( freadscan( read->buf, im->Xsize, fin ) ) {
			im_error( "rad2vips", "%s",
				_( "read error" ) );
			return( -1 );
		}
		if( im_writeline( y, im, (void *) read->buf ) )
			return( -1 );
	}

	return( 0 );
}

static int
rad2vips( const char *filename, IMAGE *out )
{
	Read *read;

#ifdef DEBUG
	printf( "rad2vips: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) ) 
		return( -1 );
	if( rad2vips_get_header( read, read->fin, read->out ) ||
		rad2vips_get_data( read, read->fin, read->out ) ) {
		read_destroy( read );
		return( -1 );
	}
	read_destroy( read );

	return( 0 );
}

static const char *rad_suffs[] = { ".hdr", NULL };

/* rad format adds no new members.
 */
typedef VipsFormat VipsFormatRad;
typedef VipsFormatClass VipsFormatRadClass;

static void
vips_format_rad_class_init( VipsFormatRadClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "rad";
	object_class->description = _( "Radiance" );

	format_class->is_a = israd;
	format_class->header = rad2vips_header;
	format_class->load = rad2vips;
	format_class->save = NULL;
	format_class->suffs = rad_suffs;
}

static void
vips_format_rad_init( VipsFormatRad *object )
{
}

G_DEFINE_TYPE( VipsFormatRad, vips_format_rad, VIPS_TYPE_FORMAT );

