/* merge two images left/right or up/down
 *
 * 22/5/14
 * 	- from vips_merge()
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

/* This is a simple wrapper over the old vips7 functions. At some point we
 * should rewrite this as a pure vips8 class and redo the vips7 functions as
 * wrappers over this.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>

#include <vips/vips.h>

typedef struct {
	VipsOperation parent_instance;

	VipsImage *ref;
	VipsImage *sec;
	VipsImage *out;
	VipsDirection direction;
	int dx;
	int dy;
	int mblend;

} VipsMerge;

typedef VipsOperationClass VipsMergeClass;

G_DEFINE_TYPE( VipsMerge, vips_merge, VIPS_TYPE_OPERATION );

static int
vips_merge_build( VipsObject *object )
{
	VipsMerge *merge = (VipsMerge *) object;

	g_object_set( merge, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_merge_parent_class )->build( object ) )
		return( -1 );

	switch( merge->direction ) { 
	case VIPS_DIRECTION_HORIZONTAL:
		if( im_lrmerge( merge->ref, merge->sec, merge->out, 
			merge->dx, merge->dy, merge->mblend ) )
			return( -1 ); 
		break;

	case VIPS_DIRECTION_VERTICAL:
		if( im_tbmerge( merge->ref, merge->sec, merge->out, 
			merge->dx, merge->dy, merge->mblend ) )
			return( -1 ); 
		break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}

static void
vips_merge_class_init( VipsMergeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "merge";
	object_class->description = _( "merge two images" );
	object_class->build = vips_merge_build;

	VIPS_ARG_IMAGE( class, "ref", 1, 
		_( "Reference" ), 
		_( "Reference image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMerge, ref ) );

	VIPS_ARG_IMAGE( class, "sec", 2, 
		_( "Secondary" ), 
		_( "Secondary image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMerge, sec ) );

	VIPS_ARG_IMAGE( class, "out", 3, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMerge, out ) );

	VIPS_ARG_ENUM( class, "direction", 4, 
		_( "Direction" ), 
		_( "Horizontal or vertcial merge" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMerge, direction ), 
		VIPS_TYPE_DIRECTION, VIPS_DIRECTION_HORIZONTAL ); 

	VIPS_ARG_INT( class, "dx", 5, 
		_( "dx" ), 
		_( "Horizontal displacement from sec to ref" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMerge, dx ),
		-100000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "dy", 6, 
		_( "dy" ), 
		_( "Vertical displacement from sec to ref" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMerge, dy ),
		-100000000, 1000000000, 1 );

	VIPS_ARG_INT( class, "mblend", 7, 
		_( "Max blend" ), 
		_( "Maximum blend size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMerge, mblend ),
		0, 10000, 10 );

}

static void
vips_merge_init( VipsMerge *merge )
{
	merge->mblend = 10;
}

/**
 * vips_merge:
 * @ref: reference image
 * @sec: secondary image
 * @out: output image
 * @direction: horizontal or vertical merge
 * @dx: displacement of ref from sec
 * @dy: displacement of ref from sec
 * @...: %NULL-terminated list of optional named arguments
 * 
 * Optional arguments:
 *
 * @mblend: maximum blend size 
 *
 * This operation joins two images left-right (with @ref on the left) or
 * up-down (with @ref above) with a smooth seam.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * @dx and @dy give the displacement of @sec relative to @ref, in other words,
 * the vector to get from the origin of @sec to the origin of @ref, in other
 * words, @dx will generally be a negative number. 
 *
 * @mblend limits  the  maximum width of the
 * blend area.  A value of "-1" means "unlimited". The two images are blended 
 * with a raised cosine. 
 *
 * Pixels with all bands equal to zero are "transparent", that
 * is, zero pixels in the overlap area do not  contribute  to  the  merge.
 * This makes it possible to join non-rectangular images.
 *
 * See also: vips_mosaic(), vips_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_merge( VipsImage *ref, VipsImage *sec, VipsImage **out, 
	VipsDirection direction, int dx, int dy, ... )
{
	va_list ap;
	int result;

	va_start( ap, dy );
	result = vips_call_split( "merge", ap, 
		ref, sec, out, direction, dx, dy );
	va_end( ap );

	return( result );
}
