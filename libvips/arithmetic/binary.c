/* base class for all binary operations
 *
 * 13/3/11
 * 	- argh, forgot to make a private array for the inputs
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "arithmetic.h"
#include "binary.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Properties.
 */
enum {
	PROP_LEFT = 1,
	PROP_RIGHT,
	PROP_LAST
}; 

G_DEFINE_ABSTRACT_TYPE( VipsBinary, vips_binary, VIPS_TYPE_ARITHMETIC );

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* For two integer types, the "largest", ie. one which can represent the
 * full range of both.
 */
static VipsBandFormat format_largest[6][6] = {
        /* UC  C   US  S   UI  I */
/* UC */ { UC, S,  US, S,  UI, I },
/* C */  { S,  C,  I,  S,  I,  I },
/* US */ { US, I,  US, I,  UI, I },
/* S */  { S,  S,  I,  S,  I,  I },
/* UI */ { UI, I,  UI, I,  UI, I },
/* I */  { I,  I,  I,  I,  I,  I }
};

/* For two formats, find one which can represent the full range of both.
 */
static VipsBandFormat
vips_format_common( VipsBandFormat a, VipsBandFormat b )
{
	if( vips_band_format_iscomplex( a ) || 
		vips_band_format_iscomplex( b ) ) {
		if( a == VIPS_FORMAT_DPCOMPLEX || 
			b == VIPS_FORMAT_DPCOMPLEX )
			return( VIPS_FORMAT_DPCOMPLEX );
		else
			return( VIPS_FORMAT_COMPLEX );

	}
	else if( vips_band_format_isfloat( a ) || 
		vips_band_format_isfloat( b ) ) {
		if( a == VIPS_FORMAT_DOUBLE || 
			b == VIPS_FORMAT_DOUBLE )
			return( VIPS_FORMAT_DOUBLE );
		else
			return( VIPS_FORMAT_FLOAT );
	}
	else 
		return( format_largest[a][b] );
}

int
vips__formatalike_vec( VipsImage **in, VipsImage **out, int n )
{
	int i;
	VipsBandFormat format;

	g_assert( n >= 1 );

	format = in[0]->BandFmt;
	for( i = 1; i < n; i++ )
		format = vips_format_common( format, in[i]->BandFmt );

	for( i = 0; i < n; i++ )
		if( im_clip2fmt( in[i], out[i], format ) )
			return( -1 );

	return( 0 );
}

int
vips__formatalike( VipsImage *in1, VipsImage *in2, 
	VipsImage *out1, VipsImage *out2 )
{
	IMAGE *in[2];
	IMAGE *out[2];

	in[0] = in1;
	in[1] = in2;
	out[0] = out1;
	out[1] = out2;

	return( vips__formatalike_vec( in, out, 2 ) );
}

/* Make an n-band image. Input 1 or n bands.
 */
int
vips__bandup( const char *domain, VipsImage *in, VipsImage *out, int n )
{
	VipsImage *bands[256];
	int i;

	if( in->Bands == n ) 
		return( im_copy( in, out ) );
	if( in->Bands != 1 ) {
		vips_error( domain, _( "not one band or %d bands" ), n );
		return( -1 );
	}
	if( n > 256 || n < 1 ) {
		im_error( domain, "%s", _( "bad bands" ) );
		return( -1 );
	}

	for( i = 0; i < n; i++ )
		bands[i] = in;

	return( im_gbandjoin( bands, out, n ) );
}

int
vips__bandalike_vec( const char *domain, 
	VipsImage **in, VipsImage **out, int n )
{
	int i;
	int max_bands;

	g_assert( n >= 1 );

	max_bands = in[0]->Bands;
	for( i = 1; i < n; i++ )
		max_bands = VIPS_MAX( max_bands, in[i]->Bands );
	for( i = 0; i < n; i++ )
		if( vips__bandup( domain, in[i], out[i], max_bands ) )
			return( -1 );

	return( 0 );
}

int
vips__bandalike( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage *out1, VipsImage *out2 )
{
	VipsImage *in[2];
	VipsImage *out[2];

	in[0] = in1;
	in[1] = in2;
	out[0] = out1;
	out[1] = out2;
	if( vips__bandalike_vec( domain, in, out, 2 ) )
		return( -1 );

	return( 0 );
}

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

/* 
 * 	FIXME ... generalise this for other classes too 
 */

static int
vips_binary_process_region( VipsRegion *or, void *seq, void *a, void *b )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsBinary *binary = VIPS_BINARY( b ); 
	VipsBinaryClass *class = VIPS_BINARY_GET_CLASS( binary ); 

	PEL *p[MAX_INPUT_IMAGES], *q;
	int i, y;

	/* Prepare all input regions and make buffer pointers.
	 */
	for( i = 0; ir[i]; i++ ) {
		if( vips_region_prepare( ir[i], &or->valid ) ) 
			return( -1 );
		p[i] = (PEL *) VIPS_REGION_ADDR( ir[i], 
			or->valid.left, or->valid.top );
	}
	p[i] = NULL;
	q = (PEL *) VIPS_REGION_ADDR( or, or->valid.left, or->valid.top );

	for( y = 0; y < or->valid.height; y++ ) {
		/* Bizarre double-cast stops a bogus gcc 4.1 compiler warning.
		 */
		class->process_line( binary, q, p[0], p[1], or->valid.width );

		for( i = 0; ir[i]; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	return( 0 );
}

static int
vips_binary_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	const char *domain = class->nickname;
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_GET_CLASS( arithmetic ); 
	VipsBinary *binary = VIPS_BINARY( object );

	VipsImage *t[4];
	VipsImage **arry;

	if( VIPS_OBJECT_CLASS( vips_binary_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( binary->left ) || 
		vips_image_pio_input( binary->right ) || 
		vips_image_pio_output( arithmetic->output ) || 
		vips_check_bands_1orn( domain, binary->left, binary->right ) ||
		vips_check_size_same( domain, binary->left, binary->right ) ||
		vips_check_uncoded( domain, binary->left ) ||
		vips_check_uncoded( domain, binary->right ) )
		return( -1 );

	if( vips_image_new_array( object, t, 4 ) )
		return( -1 );

	/* Cast our input images up to a common format and bands.
	 */
	if( vips__formatalike( binary->left, binary->right, t[0], t[1] ) ||
		vips__bandalike( domain, t[0], t[1], t[2], t[3] ) )
		return( -1 );
	binary->left_processed = t[2];
	binary->right_processed = t[3];
	if( !(arry = vips_allocate_input_array( arithmetic->output, 
		binary->left_processed, binary->right_processed, NULL )) )
		return( -1 );

	/* Hint demand style. Being a buffer processor, we are happiest with
	 * thin strips.
	 */
        if( vips_demand_hint_array( arithmetic->output, 
		VIPS_DEMAND_STYLE_THINSTRIP, arry ) ||
		vips_image_copy_fields_array( arithmetic->output, arry ) )
		return( -1 );

	arithmetic->output->Bands = t[2]->Bands;
	arithmetic->output->BandFmt = aclass->format_table[t[2]->BandFmt];

	if( vips_image_generate( arithmetic->output,
		vips_start_many, vips_binary_process_region, 
			vips_stop_many, 
		arry, binary ) )
		return( -1 );

	return( 0 );
}

static void
vips_binary_class_init( VipsBinaryClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	GParamSpec *pspec;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->build = vips_binary_build;

	/* Create properties.
	 */
	pspec = g_param_spec_object( "right", 
		"Right", "Right-hand image argument",
		VIPS_TYPE_IMAGE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_RIGHT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBinary, right ) );

	pspec = g_param_spec_object( "left", 
		"Left", "Left-hand image argument",
		VIPS_TYPE_IMAGE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_LEFT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBinary, left ) );
}

static void
vips_binary_init( VipsBinary *binary )
{
	/* Init our instance fields.
	 */
}
