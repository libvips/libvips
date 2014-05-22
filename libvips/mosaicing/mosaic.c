/* mosaic two images left/right or up/down
 *
 * 22/5/14
 * 	- from vips_mosaic()
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
	int xref;
	int yref;
	int xsec;
	int ysec;
	int mblend;
	int bandno;
	int hwindow;
	int harea;

} VipsMosaic;

typedef VipsOperationClass VipsMosaicClass;

G_DEFINE_TYPE( VipsMosaic, vips_mosaic, VIPS_TYPE_OPERATION );

static int
vips_mosaic_build( VipsObject *object )
{
	VipsMosaic *mosaic = (VipsMosaic *) object;

	g_object_set( mosaic, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_mosaic_parent_class )->build( object ) )
		return( -1 );

	switch( mosaic->direction ) { 
	case VIPS_DIRECTION_HORIZONTAL:
		if( im_lrmosaic( mosaic->ref, mosaic->sec, mosaic->out, 
			mosaic->bandno,
			mosaic->xref, mosaic->yref, 
			mosaic->xsec, mosaic->ysec, 
			mosaic->hwindow, mosaic->harea, 
			0,
			mosaic->mblend ) )
			return( -1 ); 
		break;

	case VIPS_DIRECTION_VERTICAL:
		if( im_tbmosaic( mosaic->ref, mosaic->sec, mosaic->out, 
			mosaic->bandno,
			mosaic->xref, mosaic->yref, 
			mosaic->xsec, mosaic->ysec, 
			mosaic->hwindow, mosaic->harea, 
			0,
			mosaic->mblend ) )
			return( -1 ); 
		break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}

static void
vips_mosaic_class_init( VipsMosaicClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "mosaic";
	object_class->description = _( "mosaic two images" );
	object_class->build = vips_mosaic_build;

	VIPS_ARG_IMAGE( class, "ref", 1, 
		_( "Reference" ), 
		_( "Reference image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMosaic, ref ) );

	VIPS_ARG_IMAGE( class, "sec", 2, 
		_( "Secondary" ), 
		_( "Secondary image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMosaic, sec ) );

	VIPS_ARG_IMAGE( class, "out", 3, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMosaic, out ) );

	VIPS_ARG_ENUM( class, "direction", 4, 
		_( "Direction" ), 
		_( "Horizontal or vertcial mosaic" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMosaic, direction ), 
		VIPS_TYPE_DIRECTION, VIPS_DIRECTION_HORIZONTAL ); 

	VIPS_ARG_INT( class, "xref", 5, 
		_( "xref" ), 
		_( "Position of reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic, xref ),
		0, 1000000000, 1 );

	VIPS_ARG_INT( class, "yref", 6, 
		_( "yref" ), 
		_( "Position of reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic, yref ),
		0, 1000000000, 1 );

	VIPS_ARG_INT( class, "xsec", 7, 
		_( "xsec" ), 
		_( "Position of reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic, xsec ),
		0, 1000000000, 1 );

	VIPS_ARG_INT( class, "ysec", 8, 
		_( "ysec" ), 
		_( "Position of reference tie-point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMosaic, ysec ),
		0, 1000000000, 1 );

	VIPS_ARG_INT( class, "hwindow", 9, 
		_( "hwindow" ), 
		_( "Half window size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic, hwindow ),
		0, 1000000000, 1 );

	VIPS_ARG_INT( class, "harea", 10, 
		_( "harea" ), 
		_( "Half area size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic, harea ),
		0, 1000000000, 1 );

	VIPS_ARG_INT( class, "mblend", 11, 
		_( "Max blend" ), 
		_( "Maximum blend size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic, mblend ),
		0, 10000, 10 );

	VIPS_ARG_INT( class, "bandno", 12, 
		_( "Search band" ), 
		_( "Band to search for features on" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMosaic, bandno ),
		0, 10000, 0 );

}

static void
vips_mosaic_init( VipsMosaic *mosaic )
{
	mosaic->mblend = 10;
	mosaic->hwindow = 5;
	mosaic->harea = 15;
}

/**
 * vips_mosaic:
 * @ref: reference image
 * @sec: secondary image
 * @out: output image
 * @direction: horizontal or vertical join
 * @xref: position in reference image
 * @yref: position in reference image
 * @xsec: position in secondary image
 * @ysec: position in secondary image
 * 
 * Optional arguments:
 *
 * @bandno: band to search for features
 * @hwindow: half window size
 * @harea: half search size 
 * @mblend: maximum blend size
 *
 * This operation joins two images left-right (with @ref on the left) or
 * top-bottom (with @ref above) given an approximate overlap.
 *
 * @sec is positioned so that the pixel (@xsec, @ysec) lies on top of the
 * pixel in @ref at (@xref, @yref). The overlap area is divided into three
 * sections, 20 high-contrast points in band @bandno of image @ref are found 
 * in each, and each high-contrast point is searched for in @sec using
 * @hwindow and @harea (see vips_correl()). 
 *
 * A linear model is fitted to the 60 tie-points, points a long way from the
 * fit are discarded, and the model refitted until either too few points
 * remain or the model reaches good agreement. 
 *
 * The detected displacement is used with vips_merge() to join the two images
 * together. 
 *
 * See also: vips_merge(), vips_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_mosaic( VipsImage *ref, VipsImage *sec, VipsImage **out, 
	VipsDirection direction, int xref, int yref, int xsec, int ysec, ... )
{
	va_list ap;
	int result;

	va_start( ap, ysec );
	result = vips_call_split( "mosaic", ap, ref, sec, out, 
		direction, xref, yref, xsec, ysec );
	va_end( ap );

	return( result );
}
