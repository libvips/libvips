/* load ppm from a file
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
 * 1/5/10
 * 	- add PFM (portable float map) support
 * 19/12/11
 * 	- rework as a set of fns ready to be called from a class
 * 8/11/14
 * 	- add 1 bit write
 * 29/7/19 Kyle-Kyle
 * 	- fix a loop with malformed ppm
 * 13/11/19
 * 	- redone with source/target
 * 	- sequential load, plus mmap for filename sources
 * 	- faster plus lower memory use
 * 02/02/20
 * 	- ban max_vaue < 0 
 * 27/6/20
 * 	- add ppmload_source
 * 22/11/20
 * 	- fix msb_first default [ewelot]
 * 26/12/20
 * 	- don't byteswap ascii formats
 * 	- set metadata for map loads
 * 	- byteswap binary loads
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_PPM

typedef struct _VipsForeignLoadPpm {
	VipsForeignLoad parent_object;

	/* The source we load from, and the buffered wrapper for it.
	 */
	VipsSource *source;
	VipsSbuf *sbuf;

	/* Properties of this ppm, from the header.
	 */
	int width;
	int height;
	int bands;
	VipsBandFormat format;
	VipsInterpretation interpretation;
	float scale;
	int max_value;
	int index;		/* ppm type .. index in magic_names[] */
	int bits;		/* 1, 8, 16 or 32 */
	gboolean ascii;		/* TRUE for ascii encoding */
	gboolean msb_first;	/* TRUE if most sig byte is first */

	gboolean have_read_header;

} VipsForeignLoadPpm;

typedef VipsForeignLoadClass VipsForeignLoadPpmClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadPpm, vips_foreign_load_ppm, 
	VIPS_TYPE_FOREIGN_LOAD );

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

/* Shared with ppmsave.
 */
const char *vips__ppm_suffs[] = { 
        ".pbm", ".pgm", ".ppm", ".pfm", ".pnm", NULL 
};
const char *vips__save_pbm_suffs[] = { ".pbm", NULL };
const char *vips__save_pgm_suffs[] = { ".pgm", NULL };
const char *vips__save_ppm_suffs[] = { ".ppm", NULL };
const char *vips__save_pfm_suffs[] = { ".pfm", NULL };
const char *vips__save_pnm_suffs[] = { ".pnm", NULL };

static gboolean
vips_foreign_load_ppm_is_a_source( VipsSource *source )
{
	const unsigned char *data;

	if( (data = vips_source_sniff( source, 2 )) ) { 
		int i;

		for( i = 0; i < VIPS_NUMBER( magic_names ); i++ )
			if( vips_isprefix( magic_names[i], (char *) data ) )
				return( TRUE );
	}

	return( FALSE );
}

static int
get_int( VipsSbuf *sbuf, int *i )
{
	const char *txt;

	if( vips_sbuf_skip_whitespace( sbuf ) ||
		!(txt = vips_sbuf_get_non_whitespace( sbuf )) )
		return( -1 );

	*i = atoi( txt ); 

	return( 0 );
}

static int
get_float( VipsSbuf *sbuf, float *f )
{
	const char *txt;

	if( vips_sbuf_skip_whitespace( sbuf ) ||
		!(txt = vips_sbuf_get_non_whitespace( sbuf )) )
		return( -1 );

	/* We don't want the locale str -> float conversion.
	 */
	*f = g_ascii_strtod( txt, NULL );

	return( 0 );
}

static void
vips_foreign_load_ppm_dispose( GObject *gobject )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) gobject;

#ifdef DEBUG
	printf( "vips_foreign_load_ppm_dispose: %p\n", ppm );
#endif /*DEBUG*/

	VIPS_UNREF( ppm->sbuf );
	VIPS_UNREF( ppm->source );

	G_OBJECT_CLASS( vips_foreign_load_ppm_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_ppm_build( VipsObject *object )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) object;

	if( ppm->source ) 
		ppm->sbuf = vips_sbuf_new_from_source( ppm->source );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_ppm_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

/* Scan the header into our class.
 */
static int
vips_foreign_load_ppm_parse_header( VipsForeignLoadPpm *ppm )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( ppm );

	int i;
	char buf[2];

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

	if( vips_source_rewind( ppm->source ) )
		return( -1 );

	/* Read in the magic number.
	 */
	buf[0] = VIPS_SBUF_GETC( ppm->sbuf );
	buf[1] = VIPS_SBUF_GETC( ppm->sbuf );

	for( i = 0; i < VIPS_NUMBER( magic_names ); i++ )
		if( vips_isprefix( magic_names[i], buf ) ) 
			break;
	if( i == VIPS_NUMBER( magic_names ) ) {
		vips_error( class->nickname, "%s", _( "bad magic number" ) );
		return( -1 );
	}
	ppm->index = i;
	ppm->bits = lookup_bits[i];
	ppm->bands = lookup_bands[i];
	ppm->ascii = lookup_ascii[i];

	/* Default ... can be changed below for PFM images.
	 */
	ppm->msb_first = 1;

	/* Read in size.
	 */
	if( get_int( ppm->sbuf, &ppm->width ) ||
		get_int( ppm->sbuf, &ppm->height ) )
		return( -1 );

	/* Read in max value / scale for >1 bit images.
	 */
	if( ppm->bits > 1 ) {
		if( ppm->index == 6 || 
			ppm->index == 7 ) {
			if( get_float( ppm->sbuf, &ppm->scale ) )
				return( -1 );

			/* Scale > 0 means big-endian.
			 */
			ppm->msb_first = ppm->scale > 0;
		}
		else {
			if( get_int( ppm->sbuf, &ppm->max_value ) )
				return( -1 );

			/* max_value must be > 0 and <= 65535, according to
			 * the spec, but we allow up to 32 bits per pixel.
			 */
			if( ppm->max_value < 0 )
				ppm->max_value = 0;

			if( ppm->max_value > 255 )
				ppm->bits = 16;
			if( ppm->max_value > 65535 )
				ppm->bits = 32;
		}
	}

	/* For binary images, there is always exactly 1 more whitespace
	 * character before the data starts.
	 */
	if( !ppm->ascii && 
		!isspace( VIPS_SBUF_GETC( ppm->sbuf ) ) ) {
		vips_error( class->nickname, "%s", 
			_( "no whitespace before start of binary data" ) );
		return( -1 );
	}

	/* Choose a VIPS bandfmt.
	 */
	switch( ppm->bits ) {
	case 1:
	case 8:
		ppm->format = VIPS_FORMAT_UCHAR;
		break;

	case 16:
		ppm->format = VIPS_FORMAT_USHORT;
		break;

	case 32:
		if( ppm->index == 6 || 
			ppm->index == 7 )
			ppm->format = VIPS_FORMAT_FLOAT;
		else
			ppm->format = VIPS_FORMAT_UINT;
		break;

	default:
		g_assert_not_reached();

		/* Stop compiler warnings.
		 */
		ppm->format = VIPS_FORMAT_UCHAR;
	}

	if( ppm->bands == 1 ) {
		if( ppm->format == VIPS_FORMAT_USHORT )
			ppm->interpretation = VIPS_INTERPRETATION_GREY16;
		else
			ppm->interpretation = VIPS_INTERPRETATION_B_W;
	}
	else {
		if( ppm->format == VIPS_FORMAT_USHORT )
			ppm->interpretation = VIPS_INTERPRETATION_RGB16;
		else 
			ppm->interpretation = VIPS_INTERPRETATION_sRGB;
	}

	ppm->have_read_header = TRUE;

#ifdef DEBUG
	printf( "vips_foreign_load_ppm_parse_header:\n" ); 
	printf( "\twidth = %d\n", ppm->width ); 
	printf( "\theight = %d\n", ppm->height ); 
	printf( "\tbands = %d\n", ppm->bands ); 
	printf( "\tformat = %s\n",
		vips_enum_nick( VIPS_TYPE_BAND_FORMAT, 
			ppm->format ) );
	printf( "\tinterpretation = %s\n",
		vips_enum_nick( VIPS_TYPE_INTERPRETATION, 
			ppm->interpretation ) );
	printf( "\tscale = %g\n", ppm->scale ); 
	printf( "\tmax_value = %d\n", ppm->max_value ); 
	printf( "\tbits = %d\n", ppm->bits ); 
	printf( "\tacsii = %d\n", ppm->ascii ); 
	printf( "\tmsb_first = %d\n", ppm->msb_first ); 
#endif /*DEBUG*/

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_ppm_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) load;

	VipsForeignFlags flags;

	flags = 0;

	/* If this source supports fast mmap and this PPM is >=8 bit binary,
	 * then we can mmap the file and support partial load. Otherwise,
	 * it's sequential.
	 */
	if( !ppm->have_read_header &&
		vips_foreign_load_ppm_parse_header( ppm ) )
		return( 0 );
	if( vips_source_is_mappable( ppm->source ) &&
		!ppm->ascii && 
		ppm->bits >= 8 )
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	return( flags );
}

static void
vips_foreign_load_ppm_set_image_metadata( VipsForeignLoadPpm *ppm, 
	VipsImage *image )
{
	image->Type = ppm->interpretation;

	if( ppm->index == 6 || 
		ppm->index == 7 ) 
		vips_image_set_double( image, 
			"pfm-scale", VIPS_FABS( ppm->scale ) );
	else
		vips_image_set_double( image, 
			"ppm-max-value", VIPS_ABS( ppm->max_value ) );

	VIPS_SETSTR( image->filename, vips_connection_filename( 
		VIPS_CONNECTION( ppm->sbuf->source ) ) );

#ifdef DEBUG
	printf( "vips_foreign_load_ppm_set_image: " );
	vips_object_print_summary( VIPS_OBJECT( image ) );
#endif /*DEBUG*/
}

static void
vips_foreign_load_ppm_set_image( VipsForeignLoadPpm *ppm, VipsImage *image )
{
	vips_image_init_fields( image,
		ppm->width, ppm->height, ppm->bands, ppm->format, 
		VIPS_CODING_NONE, ppm->interpretation, 1.0, 1.0 );

        (void) vips_image_pipelinev( image, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	vips_foreign_load_ppm_set_image_metadata( ppm, image );

#ifdef DEBUG
	printf( "vips_foreign_load_ppm_set_image: " );
	vips_object_print_summary( VIPS_OBJECT( image ) );
#endif /*DEBUG*/
}

static int
vips_foreign_load_ppm_header( VipsForeignLoad *load )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) load;

	if( !ppm->have_read_header &&
		vips_foreign_load_ppm_parse_header( ppm ) )
		return( 0 );

	vips_foreign_load_ppm_set_image( ppm, load->out );

	vips_source_minimise( ppm->source );

	return( 0 );
}

/* Read a ppm/pgm file using mmap().
 */
static VipsImage *
vips_foreign_load_ppm_map( VipsForeignLoadPpm *ppm )
{
	gint64 header_offset;
	size_t length;
	const void *data;
	VipsImage *out;

#ifdef DEBUG
	printf( "vips_foreign_load_ppm_map:\n" );
#endif /*DEBUG*/

	vips_sbuf_unbuffer( ppm->sbuf );
	header_offset = vips_source_seek( ppm->source, 0, SEEK_CUR );
	data = vips_source_map( ppm->source, &length );
	if( header_offset < 0 || 
		!data )
		return( NULL );
	data += header_offset;
       	length -= header_offset;

	if( !(out = vips_image_new_from_memory( data, length,
		ppm->width, ppm->height, ppm->bands, ppm->format )) )
		return( NULL );

	vips_foreign_load_ppm_set_image_metadata( ppm, out );

	return( out );
}

static int
vips_foreign_load_ppm_generate_binary( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) a;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( ppm );
	VipsImage *image = or->im;
	size_t sizeof_line = VIPS_IMAGE_SIZEOF_LINE( image );

	int y;

	for( y = 0; y < r->height; y++ ) {
		VipsPel *q = VIPS_REGION_ADDR( or, 0, r->top + y );

		size_t n_bytes;

		n_bytes = sizeof_line;
		while( n_bytes > 0 ) {
			gint64 bytes_read;

			bytes_read = 
				vips_source_read( ppm->source, q, n_bytes );
			if( bytes_read < 0 ) 
				return( -1 );
			if( bytes_read == 0 ) {
				vips_error( class->nickname, 
					"%s", _( "file truncated" ) );
				return( -1 );
			}

			q += bytes_read;
			n_bytes -= bytes_read;
		}
	}

	return( 0 );
}

static int
vips_foreign_load_ppm_generate_1bit_ascii( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) a;
	VipsImage *image = or->im;

	int x, y;

	for( y = 0; y < r->height; y++ ) {
		VipsPel *q = VIPS_REGION_ADDR( or, 0, r->top + y );

		for( x = 0; x < image->Xsize; x++ ) {
			int val;

			if( get_int( ppm->sbuf, &val ) )
				return( -1 );

			if( val )
				q[x] = 0;
			else
				q[x] = 255;
		}
	}

	return( 0 );
}

static int
vips_foreign_load_ppm_generate_1bit_binary( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) a;
	VipsImage *image = or->im;

	int x, y;

	for( y = 0; y < r->height; y++ ) {
		VipsPel *q = VIPS_REGION_ADDR( or, 0, r->top + y );

		int bits;

		/* Not needed, but stop a compiler warning.
		 */
		bits = 0;

		for( x = 0; x < image->Xsize; x++ ) {
			if( (x & 7) == 0 )
				bits = VIPS_SBUF_GETC( ppm->sbuf );
			q[x] = (bits & 128) ? 0 : 255;
			bits = VIPS_LSHIFT_INT( bits, 1 );
		}
	}

	return( 0 );
}

static int
vips_foreign_load_ppm_generate_ascii_int( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) a;
	VipsImage *image = or->im;
	int n_elements = image->Xsize * image->Bands;

	int i, y;

	for( y = 0; y < r->height; y++ ) {
		VipsPel *q = VIPS_REGION_ADDR( or, r->left, r->top + y );

		for( i = 0; i < n_elements; i++ ) {
			int val;

			if( get_int( ppm->sbuf, &val ) )
				return( -1 );
			
			switch( image->BandFmt ) {
			case VIPS_FORMAT_UCHAR:
				q[i] = VIPS_CLIP( 0, val, 255 );
				break;

			case VIPS_FORMAT_USHORT:
				((unsigned short *) q)[i] = 
					VIPS_CLIP( 0, val, 65535 );
				break;

			case VIPS_FORMAT_UINT:
				((unsigned int *) q)[i] = val;
				break;

			default:
				g_assert_not_reached();
			}
		}
	}

	return( 0 );
}

static VipsImage *
vips_foreign_load_ppm_scan( VipsForeignLoadPpm *ppm )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( ppm ), 2 );

	VipsImage *out;
	VipsGenerateFn generate;

	/* What sort of read are we doing?
	 */
	if( !ppm->ascii && ppm->bits >= 8 ) {
#ifdef DEBUG
		printf( "vips_foreign_load_ppm_source: >1 bit binary load\n" );
#endif /*DEBUG*/

		generate = vips_foreign_load_ppm_generate_binary;

		/* The binary loader does not use the buffered IO 
		 * object.
		 */
		vips_sbuf_unbuffer( ppm->sbuf ); 
	}
	else if( !ppm->ascii && ppm->bits == 1 ) {
#ifdef DEBUG
		printf( "vips_foreign_load_ppm_source: 1-bit binary load\n" );
#endif /*DEBUG*/

		generate = vips_foreign_load_ppm_generate_1bit_binary;
	}
	else if( ppm->ascii && ppm->bits == 1 ) {
#ifdef DEBUG
		printf( "vips_foreign_load_ppm_source: 1-bit ascii load\n" );
#endif /*DEBUG*/

		generate = vips_foreign_load_ppm_generate_1bit_ascii;
	}
	else {
#ifdef DEBUG
		printf( "vips_foreign_load_ppm_source: >1-bit ascii load\n" );
#endif /*DEBUG*/

		generate = vips_foreign_load_ppm_generate_ascii_int;
	}

	t[0] = vips_image_new(); 
	vips_foreign_load_ppm_set_image( ppm, t[0] );
	if( vips_image_generate( t[0], NULL, generate, NULL, ppm, NULL ) ||
		vips_sequential( t[0], &out, NULL ) )
		return( NULL );

	return( out );
}

static int
vips_foreign_load_ppm_load( VipsForeignLoad *load )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) load, 2 );

	if( !ppm->have_read_header &&
		vips_foreign_load_ppm_parse_header( ppm ) )
		return( 0 );

	/* If the source is mappable and this is a binary file, we can map it.
	 */
	if( vips_source_is_mappable( ppm->source ) &&
		!ppm->ascii && 
		ppm->bits >= 8 ) {
		if( !(t[0] = vips_foreign_load_ppm_map( ppm )) ) 
			return( -1 );
	}
	else {
		if( !(t[0] = vips_foreign_load_ppm_scan( ppm )) ) 
			return( -1 );
	}

#ifdef DEBUG
	printf( "vips_foreign_load_ppm: byteswap = %d\n", 
		vips_amiMSBfirst() != ppm->msb_first );
#endif /*DEBUG*/

	/* Don't byteswap the ascii formats.
	 */
	if( vips__byteswap_bool( t[0], &t[1],
			!ppm->ascii &&
                        vips_amiMSBfirst() != ppm->msb_first ) ||
		vips_image_write( t[1], load->real ) ) 
		return( -1 );

	if( vips_source_decode( ppm->source ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_ppm_class_init( VipsForeignLoadPpmClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_ppm_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "ppmload_base";
	object_class->description = _( "load ppm base class" );
	object_class->build = vips_foreign_load_ppm_build;

	/* You're unlikely to want to use this on untrusted files.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	foreign_class->suffs = vips__ppm_suffs;

	/* We are fast at is_a(), so high priority.
	 */
	foreign_class->priority = 200;

	load_class->get_flags = vips_foreign_load_ppm_get_flags;
	load_class->header = vips_foreign_load_ppm_header;
	load_class->load = vips_foreign_load_ppm_load;

}

static void
vips_foreign_load_ppm_init( VipsForeignLoadPpm *ppm )
{
	ppm->scale = 1.0;
}

typedef struct _VipsForeignLoadPpmFile {
	VipsForeignLoadPpm parent_object;

	char *filename;

} VipsForeignLoadPpmFile;

typedef VipsForeignLoadPpmClass VipsForeignLoadPpmFileClass;

G_DEFINE_TYPE( VipsForeignLoadPpmFile, vips_foreign_load_ppm_file, 
	vips_foreign_load_ppm_get_type() );

static gboolean
vips_foreign_load_ppm_file_is_a( const char *filename )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_ppm_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static int
vips_foreign_load_ppm_file_build( VipsObject *object )
{
	VipsForeignLoadPpmFile *file = (VipsForeignLoadPpmFile *) object;
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) object;

	if( file->filename &&
		!(ppm->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_ppm_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_ppm_file_class_init( VipsForeignLoadPpmClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "ppmload";
	object_class->description = _( "load ppm from file" );
	object_class->build = vips_foreign_load_ppm_file_build;

	load_class->is_a = vips_foreign_load_ppm_file_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPpmFile, filename ),
		NULL );
}

static void
vips_foreign_load_ppm_file_init( VipsForeignLoadPpmFile *file )
{
}

typedef struct _VipsForeignLoadPpmSource {
	VipsForeignLoadPpm parent_object;

	VipsSource *source;

} VipsForeignLoadPpmSource;

typedef VipsForeignLoadPpmClass VipsForeignLoadPpmSourceClass;

G_DEFINE_TYPE( VipsForeignLoadPpmSource, vips_foreign_load_ppm_source,
	vips_foreign_load_ppm_get_type() );

static int
vips_foreign_load_ppm_source_build( VipsObject *object )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) object;
	VipsForeignLoadPpmSource *source = (VipsForeignLoadPpmSource *) object;

	if( source->source ) {
		ppm->source = source->source;
		g_object_ref( ppm->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_ppm_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_ppm_source_class_init( VipsForeignLoadPpmFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "ppmload_source";
	object_class->build = vips_foreign_load_ppm_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_ppm_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPpmSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_ppm_source_init( VipsForeignLoadPpmSource *source )
{
}

#endif /*HAVE_PPM*/

/**
 * vips_ppmload:
 * @filename: file to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a PPM/PBM/PGM/PFM file into a VIPS image. 
 *
 * It can read 1, 8, 16 and 32 bit images, colour or monochrome,
 * stored in binary or in ASCII. One bit images become 8 bit VIPS images, 
 * with 0 and 255 for 0 and 1.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_ppmload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "ppmload", ap, filename, out ); 
	va_end( ap );

	return( result );
}

/**
 * vips_ppmload_source:
 * @source: source to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @skip: skip this many lines at start of file
 * * @lines: read this many lines from file
 * * @whitespace: set of whitespace characters
 * * @separator: set of separator characters
 * * @fail: %gboolean, fail on errors
 *
 * Exactly as vips_ppmload(), but read from a source. 
 *
 * See also: vips_ppmload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_ppmload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "ppmload_source", ap, source, out ); 
	va_end( ap );

	return( result );
}
