/* load nifti from a file
 *
 * 29/6/18
 * 	- from fitsload.c
 * 9/9/19
 * 	- use double for all floating point scalar metadata, like other loaders
 * 	- remove stray use of "n" property
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
#define VIPS_DEBUG
 */

/* TODO
 *
 * - for uncompressed images, we could do direct mapping of the input
 * - perhaps we could stream compressed images? but only if ext is defined at 
 *   the start of the file
 *   	(yes, file format is magic number, 348-byte header, extension data,
 *   	pixel data, then all gz'd)
 * - we could use the much faster byteswap in glib?
 * - I have not been able to test the ext stuff :( 
 *
 * There should be at least a x2 speedup possible.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef HAVE_NIFTI

#include <nifti1_io.h>

#include "pforeign.h"

typedef struct _VipsForeignLoadNifti {
	VipsForeignLoad parent_object;

	/* Source to load from (set by subclasses).
	 */
	VipsSource *source;

	/* Filename from source.
	 */
	const char *filename;

	/* The NIFTI image loaded to memory.
	 */
	nifti_image *nim;

	/* Wrap this VipsImage around the NIFTI pointer, then redirect read
	 * requests to that. Saves a copy. 
	 */
	VipsImage *memory;

} VipsForeignLoadNifti;

typedef VipsForeignLoadClass VipsForeignLoadNiftiClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadNifti, vips_foreign_load_nifti, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_nifti_dispose( GObject *gobject )
{
	VipsForeignLoadNifti *nifti = (VipsForeignLoadNifti *) gobject;

	VIPS_UNREF( nifti->source );
	VIPS_UNREF( nifti->memory );
	VIPS_FREEF( nifti_image_free, nifti->nim );

	G_OBJECT_CLASS( vips_foreign_load_nifti_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_nifti_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignLoadNifti *nifti = (VipsForeignLoadNifti *) object;

	/* We can only open source which have an associated filename, since
	 * the nifti library works in terms of filenames.
	 */
	if( nifti->source ) {
		VipsConnection *connection = VIPS_CONNECTION( nifti->source );

		const char *filename;

		if( !vips_source_is_file( nifti->source ) ||
			!(filename = vips_connection_filename( connection )) ) {
			vips_error( class->nickname, 
				"%s", _( "no filename available" ) );
			return( -1 );
		}

		nifti->filename = filename; 
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_nifti_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

/* Map DT_* datatype values to VipsBandFormat.
 */
typedef struct _VipsForeignDT2Vips {
	int datatype;
	VipsBandFormat fmt;
} VipsForeignDT2Vips ;

static VipsForeignDT2Vips vips_foreign_nifti_DT2Vips[] = {
	{ DT_UINT8, VIPS_FORMAT_UCHAR },
	{ DT_INT8, VIPS_FORMAT_CHAR },
	{ DT_UINT16, VIPS_FORMAT_USHORT },
	{ DT_INT16, VIPS_FORMAT_SHORT },
	{ DT_UINT32, VIPS_FORMAT_UINT },
	{ DT_INT32, VIPS_FORMAT_INT },
	{ DT_FLOAT32, VIPS_FORMAT_FLOAT },
	{ DT_FLOAT64, VIPS_FORMAT_DOUBLE },
	{ DT_COMPLEX64, VIPS_FORMAT_COMPLEX },
	{ DT_COMPLEX128, VIPS_FORMAT_DPCOMPLEX },
	{ DT_RGB, VIPS_FORMAT_UCHAR },
	{ DT_RGBA32, VIPS_FORMAT_UCHAR }
};

VipsBandFormat
vips__foreign_nifti_datatype2BandFmt( int datatype )
{
	int i;

	for( i = 0; i < VIPS_NUMBER( vips_foreign_nifti_DT2Vips ); i++ )
		if( vips_foreign_nifti_DT2Vips[i].datatype == datatype )
			return( vips_foreign_nifti_DT2Vips[i].fmt );

	return( VIPS_FORMAT_NOTSET );
}

int
vips__foreign_nifti_BandFmt2datatype( VipsBandFormat fmt )
{
	int i;

	for( i = 0; i < VIPS_NUMBER( vips_foreign_nifti_DT2Vips ); i++ )
		if( vips_foreign_nifti_DT2Vips[i].fmt == fmt )
			return( vips_foreign_nifti_DT2Vips[i].datatype );

	return( -1 );
}

/* All the header fields we attach as metadata.
 */
typedef struct _VipsForeignNiftiFields {
	char *name;
	GType type;
	glong offset;
} VipsForeignNiftiFields;

static VipsForeignNiftiFields vips_foreign_nifti_fields[] = {
	/* The first 8 must be the dims[] fields, see
	 * vips_foreign_save_nifti_make_nim().
	 */
	{ "ndim", G_TYPE_INT, G_STRUCT_OFFSET( nifti_image, ndim ) }, 
	{ "nx", G_TYPE_INT, G_STRUCT_OFFSET( nifti_image, nx ) }, 
	{ "ny", G_TYPE_INT, G_STRUCT_OFFSET( nifti_image, ny ) }, 
	{ "nz", G_TYPE_INT, G_STRUCT_OFFSET( nifti_image, nz ) }, 
	{ "nt", G_TYPE_INT, G_STRUCT_OFFSET( nifti_image, nt ) }, 
	{ "nu", G_TYPE_INT, G_STRUCT_OFFSET( nifti_image, nu ) }, 
	{ "nv", G_TYPE_INT, G_STRUCT_OFFSET( nifti_image, nv ) }, 
	{ "nw", G_TYPE_INT, G_STRUCT_OFFSET( nifti_image, nw ) }, 

	{ "dx", G_TYPE_DOUBLE, G_STRUCT_OFFSET( nifti_image, dx ) }, 
	{ "dy", G_TYPE_DOUBLE, G_STRUCT_OFFSET( nifti_image, dy ) }, 
	{ "dz", G_TYPE_DOUBLE, G_STRUCT_OFFSET( nifti_image, dz ) }, 
	{ "dt", G_TYPE_DOUBLE, G_STRUCT_OFFSET( nifti_image, dt ) }, 
	{ "du", G_TYPE_DOUBLE, G_STRUCT_OFFSET( nifti_image, du ) }, 
	{ "dv", G_TYPE_DOUBLE, G_STRUCT_OFFSET( nifti_image, dv ) }, 
	{ "dw", G_TYPE_DOUBLE, G_STRUCT_OFFSET( nifti_image, dw ) }, 

	{ "scl_slope", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, scl_slope ) }, 
	{ "scl_inter", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, scl_inter ) }, 

	{ "cal_min", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, cal_min ) }, 
	{ "cal_max", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, cal_max ) }, 

	{ "qform_code", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, qform_code ) }, 
	{ "sform_code", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, sform_code ) }, 

	{ "freq_dim", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, freq_dim ) }, 
	{ "phase_dim", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, phase_dim ) }, 
	{ "slice_dim", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, slice_dim ) }, 

	{ "slice_code", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, slice_code ) }, 
	{ "slice_start", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, slice_start ) }, 
	{ "slice_end", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, slice_end ) }, 
	{ "slice_duration", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, slice_duration ) }, 

	{ "quatern_b", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, quatern_b ) }, 
	{ "quatern_c", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, quatern_c ) }, 
	{ "quatern_d", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, quatern_d ) }, 
	{ "qoffset_x", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, qoffset_x ) }, 
	{ "qoffset_y", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, qoffset_y ) }, 
	{ "qoffset_z", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, qoffset_z ) }, 
	{ "qfac", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, qfac ) }, 

	{ "sto_xyz00", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[0][0] ) }, 
	{ "sto_xyz01", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[0][1] ) }, 
	{ "sto_xyz02", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[0][2] ) }, 
	{ "sto_xyz03", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[0][3] ) }, 

	{ "sto_xyz10", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[1][0] ) }, 
	{ "sto_xyz11", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[1][1] ) }, 
	{ "sto_xyz12", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[1][2] ) }, 
	{ "sto_xyz13", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[1][3] ) }, 

	{ "sto_xyz20", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[2][0] ) }, 
	{ "sto_xyz21", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[2][1] ) }, 
	{ "sto_xyz22", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[2][2] ) }, 
	{ "sto_xyz23", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[2][3] ) }, 

	{ "sto_xyz30", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[3][0] ) }, 
	{ "sto_xyz31", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[3][1] ) }, 
	{ "sto_xyz32", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[3][2] ) }, 
	{ "sto_xyz33", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, sto_xyz.m[3][3] ) }, 

	{ "toffset", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, toffset ) }, 

	{ "xyz_units", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, xyz_units ) }, 
	{ "time_units", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, time_units ) }, 

	{ "nifti_type", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, nifti_type ) }, 
	{ "intent_code", G_TYPE_INT, 
		G_STRUCT_OFFSET( nifti_image, intent_code ) }, 
	{ "intent_p1", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, intent_p1 ) }, 
	{ "intent_p2", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, intent_p2 ) }, 
	{ "intent_p3", G_TYPE_DOUBLE, 
		G_STRUCT_OFFSET( nifti_image, intent_p3 ) }, 
};

void *
vips__foreign_nifti_map( VipsNiftiMapFn fn, void *a, void *b )
{
	int i;
	void *result;

	for( i = 0; i < VIPS_NUMBER( vips_foreign_nifti_fields ); i++ ) {
		GValue value = { 0 };

		g_value_init( &value, vips_foreign_nifti_fields[i].type );
		result = fn( vips_foreign_nifti_fields[i].name, &value,
			vips_foreign_nifti_fields[i].offset, a, b );
		g_value_unset( &value );

		if( result )
			return( result );
	}

	return( NULL );
}

/* How I wish glib had something like this :( Just implement the ones we need
 * for vips_foreign_nifti_fields above.
 */
static void
vips_gvalue_read( GValue *value, void *p )
{
	switch( G_VALUE_TYPE( value ) ) {
	case G_TYPE_INT:
		g_value_set_int( value, *((int *) p) );
		break;

	case G_TYPE_DOUBLE:
		/* We set as double rather than float, as things like pyvips
		 * expect double for metadata items.
		 */
		g_value_set_double( value, *((float *) p) );
		break;

	default:
		g_warning( "vips_gvalue_read: unsupported GType %s", 
			g_type_name( G_VALUE_TYPE( value ) ) );
	}
}

static void *
vips_foreign_load_nifti_set( const char *name, GValue *value, glong offset,
	void *a, void *b )
{
	nifti_image *nim = (nifti_image *) a;
	VipsImage *out = VIPS_IMAGE( b );

	char vips_name[256];

	vips_gvalue_read( value, (gpointer) nim + offset );
	vips_snprintf( vips_name, 256, "nifti-%s", name );
	vips_image_set( out, vips_name, value );

	return( NULL );
}

static int
vips_foreign_load_nifti_set_header( VipsForeignLoadNifti *nifti,
	nifti_image *nim, VipsImage *out )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( nifti );

	guint width;
	guint height;
	guint bands;
	VipsBandFormat fmt;
	double xres;
	double yres;
	int i;
	char txt[256];

	if( nim->ndim < 1 ||
		nim->ndim > 7 ) {
		vips_error( class->nickname, 
			_( "%d-dimensional images not supported" ), 
			nim->ndim ); 
		return( 0 );
	}
	for( i = 1; i < 8 && i < nim->ndim + 1; i++ ) {
		if( nim->dim[i] <= 0 ) {
			vips_error( class->nickname, 
				"%s", _( "invalid dimension" ) ); 
			return( 0 );
		}

		/* If we have several images in a dimension, the spacing must
		 * be non-zero or we'll get a /0 error in resolution
		 * calculation.
		 */
		if( nim->dim[i] > 1 && 
			nim->pixdim[i] == 0 ) {
			vips_error( class->nickname, 
				"%s", _( "invalid resolution" ) ); 
			return( 0 );
		}
	}

	/* Unfold higher dimensions vertically. bands is updated below for
	 * DT_RGB. Be careful to avoid height going over 2^31.
	 */
	bands = 1;
	width = (guint) nim->nx;
	height = (guint) nim->ny;
	for( i = 3; i < 8 && i < nim->ndim + 1; i++ )
		if( !g_uint_checked_mul( &height, height, nim->dim[i] ) ) {
			vips_error( class->nickname, 
				"%s", _( "dimension overflow" ) ); 
			return( 0 );
		}
	if( height > INT_MAX ) {
		vips_error( class->nickname, "%s", _( "dimension overflow" ) ); 
		return( 0 );
	}

	fmt = vips__foreign_nifti_datatype2BandFmt( nim->datatype );
	if( fmt == VIPS_FORMAT_NOTSET ) { 
		vips_error( class->nickname, 
			_( "datatype %d not supported" ), nim->datatype );
		return( -1 );
	}

	if( nim->datatype == DT_RGB )
		bands = 3;
	if( nim->datatype == DT_RGBA32 )
		bands = 4;

	/* We fold y and z together, so they must have the same resolution..
	 */
	xres = 1.0;
	yres = 1.0;
	if( nim->nz == 1 ||
		nim->dz == nim->dy ) 
		switch( nim->xyz_units ) {
		case NIFTI_UNITS_METER:
			xres = 1000.0 / nim->dx; 
			yres = 1000.0 / nim->dy; 
			break; 
		case NIFTI_UNITS_MM:
			xres = 1.0 / nim->dx; 
			yres = 1.0 / nim->dy; 
			break;

		case NIFTI_UNITS_MICRON:
			xres = 1.0 / (1000.0 * nim->dx); 
			yres = 1.0 / (1000.0 * nim->dy); 
			break;

		default:
			break;
		}

#ifdef DEBUG
	printf( "get_vips_properties: width = %d\n", width );
	printf( "get_vips_properties: height = %d\n", height );
	printf( "get_vips_properties: bands = %d\n", bands );
	printf( "get_vips_properties: fmt = %d\n", fmt );
#endif /*DEBUG*/

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );
	vips_image_init_fields( out,
		width, height, bands, fmt, 
		VIPS_CODING_NONE, 
		bands == 1 ? 
			VIPS_INTERPRETATION_B_W : VIPS_INTERPRETATION_sRGB, 
		xres, yres );

	/* Set some vips metadata for every nifti header field.
	 */
	if( vips__foreign_nifti_map( vips_foreign_load_nifti_set, nim, out ) )
		return( -1 ); 

	/* One byte longer than the spec to leave space for any extra
	 * '\0' termination.
	 */
	vips_strncpy( txt, nim->intent_name, 17 );
	vips_image_set_string( out, "nifti-intent_name", txt );
	vips_strncpy( txt, nim->descrip, 81 );
	vips_image_set_string( out, "nifti-descrip", txt );

	for( i = 0; i < nim->num_ext; i++ ) {
		nifti1_extension *ext = &nim->ext_list[i];

		vips_snprintf( txt, 256, "nifti-ext-%d-%d", i, ext->ecode );
		vips_image_set_blob_copy( out, txt, ext->edata, ext->esize );
	}

	vips_image_set_int( out, VIPS_META_PAGE_HEIGHT, nim->ny );

	return( 0 );
}

static int
vips_foreign_load_nifti_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadNifti *nifti = (VipsForeignLoadNifti *) load;

	/* We can't use the (much faster) nifti_read_header() since it just
	 * reads the 348 bytes of the analyze struct and does not read any of
	 * the extension fields.
	 */

	/* FALSE means don't read data, just the header. Use
	 * nifti_image_load() later to pull the data in.
	 */
	if( !(nifti->nim = nifti_image_read( nifti->filename, FALSE )) ) { 
		vips_error( class->nickname, 
			"%s", _( "unable to read NIFTI header" ) );
		return( 0 );
	}

	if( vips_foreign_load_nifti_set_header( nifti, 
		nifti->nim, load->out ) ) {
		return( -1 );
	}

	VIPS_SETSTR( load->out->filename, nifti->filename );

	return( 0 );
}

static int
vips_foreign_load_nifti_load( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadNifti *nifti = (VipsForeignLoadNifti *) load;

#ifdef DEBUG
	printf( "vips_foreign_load_nifti_load: loading image\n" );
#endif /*DEBUG*/

	/* We just read the entire image to memory. 
	 */
	if( nifti_image_load( nifti->nim ) ) {
		vips_error( class->nickname, 
			"%s", _( "unable to load NIFTI file" ) );
		return( -1 );
	}

	if( !(nifti->memory = vips_image_new_from_memory( 
		nifti->nim->data, VIPS_IMAGE_SIZEOF_IMAGE( load->out ),
		load->out->Xsize, load->out->Ysize, 
		load->out->Bands, load->out->BandFmt )) ) 
		return( -1 );

	if( vips_image_write( nifti->memory, load->real ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_nifti_class_init( VipsForeignLoadNiftiClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_nifti_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "niftiload_base";
	object_class->description = _( "load a NIFTI image" );
	object_class->build = vips_foreign_load_nifti_build;

	/* nificlib has not been fuzzed, so should not be used with
	 * untrusted input unless you are very careful.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -50;

	load_class->header = vips_foreign_load_nifti_header;
	load_class->load = vips_foreign_load_nifti_load;
}

static void
vips_foreign_load_nifti_init( VipsForeignLoadNifti *nifti )
{
}

typedef struct _VipsForeignLoadNiftiFile {
	VipsForeignLoadNifti parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadNiftiFile;

typedef VipsForeignLoadNiftiClass VipsForeignLoadNiftiFileClass;

G_DEFINE_TYPE( VipsForeignLoadNiftiFile, vips_foreign_load_nifti_file, 
	vips_foreign_load_nifti_get_type() );

static int
vips_foreign_load_nifti_file_build( VipsObject *object )
{
	VipsForeignLoadNifti *nifti = (VipsForeignLoadNifti *) object;
	VipsForeignLoadNiftiFile *file = (VipsForeignLoadNiftiFile *) object;

	if( file->filename &&
		!(nifti->source = 
			vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_nifti_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

const char *vips_foreign_nifti_suffs[] = { 
	".nii", ".nii.gz", 
	".hdr", ".hdr.gz", 
	".img", ".img.gz", 
	".nia", ".nia.gz", 
	NULL 
};

static int
vips_foreign_load_nifti_is_a( const char *filename )
{
	char *hfile;
	znzFile fp;
	nifti_1_header nhdr;

	/* Unfortunately is_nifti_file() is very slow and produces lots of
	 * output. We have to make our own.
	 */

	if( !(hfile = nifti_findhdrname( filename )) )
		return( 0 );

	fp = znzopen( hfile, "rb", nifti_is_gzfile( hfile ));
	if( znz_isnull( fp ) ) { 
		free( hfile );
		return( 0 );
	}
	free( hfile );

	(void) znzread( &nhdr, 1, sizeof( nhdr ), fp );

	znzclose( fp );

	/* Test for sanity both ways around. There's a thing to test for byte
	 * order in niftilib, but it's static :(
	 */
	if( nifti_hdr_looks_good( &nhdr ) ) 
		return( 1 );
	swap_nifti_header( &nhdr, FALSE );
	if( nifti_hdr_looks_good( &nhdr ) ) 
		return( 1 );

	return( 0 );
}

static void
vips_foreign_load_nifti_file_class_init( 
	VipsForeignLoadNiftiFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "niftiload";
	object_class->description = _( "load NIfTI volume" );
	object_class->build = vips_foreign_load_nifti_file_build;

	foreign_class->suffs = vips_foreign_nifti_suffs;

	load_class->is_a = vips_foreign_load_nifti_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadNiftiFile, filename ),
		NULL );

}

static void
vips_foreign_load_nifti_file_init( VipsForeignLoadNiftiFile *nifti )
{
}

typedef struct _VipsForeignLoadNiftiSource {
	VipsForeignLoadNifti parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadNiftiSource;

typedef VipsForeignLoadNiftiClass VipsForeignLoadNiftiSourceClass;

G_DEFINE_TYPE( VipsForeignLoadNiftiSource, vips_foreign_load_nifti_source, 
	vips_foreign_load_nifti_get_type() );

static int
vips_foreign_load_nifti_source_build( VipsObject *object )
{
	VipsForeignLoadNifti *nifti = (VipsForeignLoadNifti *) object;
	VipsForeignLoadNiftiSource *source = 
		(VipsForeignLoadNiftiSource *) object;

	if( source->source ) {
		nifti->source = source->source;
		g_object_ref( nifti->source );
	}

	if( VIPS_OBJECT_CLASS( 
		vips_foreign_load_nifti_source_parent_class )->
			build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_nifti_source_is_a_source( VipsSource *source )
{
	VipsConnection *connection = VIPS_CONNECTION( source );

	const char *filename;

	return( vips_source_is_file( source ) &&
		(filename = vips_connection_filename( connection )) &&
		vips_foreign_load_nifti_is_a( filename ) );
}

static void
vips_foreign_load_nifti_source_class_init( 
	VipsForeignLoadNiftiSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "niftiload_source";
	object_class->description = _( "load NIfTI volumes" );
	object_class->build = vips_foreign_load_nifti_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = 
		vips_foreign_load_nifti_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadNiftiSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_nifti_source_init( 
	VipsForeignLoadNiftiSource *nifti )
{
}

#endif /*HAVE_NIFTI*/

/**
 * vips_niftiload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a NIFTI image file into a VIPS image. 
 *
 * NIFTI metadata is attached with the "nifti-" prefix.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_niftiload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "niftiload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_niftiload_source:
 * @source: source to load from
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_niftiload(), but read from a source. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_niftiload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "niftiload_source", ap, source, out );
	va_end( ap );

	return( result );
}
