/* identity LUTs
 *
 * Copyright 1991, N. Dessipris.
 *
 * Author N. Dessipris
 * Written on 11/03/1991
 * Updated on: 
 * 18/6/93 JC
 *	- im_outcheck() call added
 *	- ANSIfied
 * 24/8/94 JC
 *	- im_identity_ushort() added
 * 24/3/10
 * 	- gtkdoc
 * 3/7/13
 * 	- redo as a class
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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "pcreate.h"

typedef struct _VipsIdentity {
	VipsCreate parent_instance;

	int bands;
	gboolean ushort;
	int size;

} VipsIdentity;

typedef VipsCreateClass VipsIdentityClass;

G_DEFINE_TYPE( VipsIdentity, vips_identity, VIPS_TYPE_CREATE );

#define IDENTITY( TYPE ) { \
	TYPE *q = (TYPE *) VIPS_REGION_ADDR( or, le, 0 ); \
	\
	for( x = le; x < ri; x++ ) { \
		for( i = 0; i < identity->bands; i++ ) \
			q[i] = x; \
		\
		q += identity->bands; \
	} \
}

static int
vips_identity_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsIdentity *identity = (VipsIdentity *) a;
	VipsRect *r = &or->valid;
	int le = r->left;
	int ri = VIPS_RECT_RIGHT( r );

	int x, i;

	if( identity->ushort ) {
		IDENTITY( unsigned short );
	}
	else {
		IDENTITY( unsigned char );
	}

	return( 0 );
}

static int
vips_identity_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsIdentity *identity = (VipsIdentity *) object;

	if( VIPS_OBJECT_CLASS( vips_identity_parent_class )->build( object ) )
		return( -1 );

	vips_image_init_fields( create->out,
		identity->ushort ? identity->size : 256, 1, identity->bands, 
		identity->ushort ? VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_HISTOGRAM,
		1.0, 1.0 );

	vips_image_pipelinev( create->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );

	if( vips_image_generate( create->out, 
		NULL, vips_identity_gen, NULL, identity, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_identity_class_init( VipsIdentityClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "identity";
	vobject_class->description = 
		_( "make a 1D image where pixel values are indexes" );
	vobject_class->build = vips_identity_build;

	VIPS_ARG_INT( class, "bands", 3, 
		_( "Bands" ), 
		_( "Number of bands in LUT" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsIdentity, bands ),
		1, 100000, 1 );

	VIPS_ARG_BOOL( class, "ushort", 4, 
		_( "Ushort" ), 
		_( "Create a 16-bit LUT" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsIdentity, ushort ),
		FALSE ); 

	VIPS_ARG_INT( class, "size", 5, 
		_( "Size" ), 
		_( "Size of 16-bit LUT" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsIdentity, size ),
		1, 65536, 65536 );

}

static void
vips_identity_init( VipsIdentity *identity )
{
	identity->bands = 1;
	identity->ushort = FALSE;
	identity->size = 65536;
}

/**
 * vips_identity:
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @bands: number of bands to create
 * @ushort: %TRUE for an unsigned short identity
 * @size: number of LUT elements for a ushort image
 *
 * Creates an identity lookup table, ie. one which will leave an image
 * unchanged when applied with vips_maplut(). Each entry in the table has a
 * value equal to its position. 
 *
 * Use the arithmetic operations on these tables to make LUTs representing
 * arbitrary functions. 
 *
 * Normally LUTs are 8-bit. Set @ushort to create a 16-bit table. 
 *
 * Normally 16-bit tables have 65536 entries. You can set this smaller with
 * @size. 
 *
 * See also: vips_xyz(), vips_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_identity( VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "identity", ap, out ); 
	va_end( ap );

	return( result );
}
