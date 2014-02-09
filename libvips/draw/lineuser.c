/* call a user function along a line ... useful for vips7 compat
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 24/10/03 JC
 *	- now blends with 0-255 user
 * 5/12/06
 * 	- im_invalidate() after paint
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 28/9/10
 * 	- gtk-doc
 * 	- renamed as im_draw_user()
 * 	- use Draw base class
 * 6/2/14
 * 	- now a subclass of VipsLine
 * 9/2/14
 * 	- from lineuser
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

#include <vips/vips.h>

#include "pdraw.h"
#include "line.h"

typedef struct _VipsLineUser {
	VipsLine parent_object;

	VipsPlotFn plot_fn;
	void *a;
	void *b;
	void *c;

} VipsLineUser;

typedef VipsLineClass VipsLineUserClass;

G_DEFINE_TYPE( VipsLineUser, vips_line_user, VIPS_TYPE_LINE );

static int
vips_line_user_plot_point( VipsLine *line, int x, int y ) 
{
	VipsDraw *draw = (VipsDraw *) line;
	VipsLineUser *line_user = (VipsLineUser *) line;

	return( line_user->plot_fn( draw->image, 
		x, y, line_user->a, line_user->b, line_user->c ) ); 
}

static void
vips_line_user_class_init( VipsLineUserClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = (VipsOperationClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "line_user";
	vobject_class->description = _( "call a plot function along a line" ); 

	operation_class->flags = VIPS_OPERATION_DEPRECATED;

	class->plot_point = vips_line_user_plot_point; 

	VIPS_ARG_POINTER( class, "plot_fn", 7, 
		_( "Plot" ), 
		_( "User plot function" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLineUser, plot_fn ) ); 

	VIPS_ARG_POINTER( class, "a", 8, 
		_( "a" ), 
		_( "first user argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLineUser, a ) ); 

	VIPS_ARG_POINTER( class, "b", 9, 
		_( "b" ), 
		_( "second user argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLineUser, b ) ); 

	VIPS_ARG_POINTER( class, "c", 10, 
		_( "c" ), 
		_( "third user argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLineUser, c ) ); 

}

static void
vips_line_user_init( VipsLineUser *line_user )
{
}

/**
 * vips_line_user:
 * @image: image to draw on
 * @x1: start of line
 * @y1: start of line
 * @x2: end of line
 * @y2: end of line
 * @user: plot function to call along line
 * @a: user plot function argument 
 * @b: user plot function argument 
 * @c: user plot function argument 
 *
 * Calls a user plot function for every point on a line. This is mostly useful
 * for vips7 compatibility. 
 *
 * See also: vips_line(), vips_line_mask().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_line_user( VipsImage *image, 
	int x1, int y1, int x2, int y2, 
	VipsPlotFn plot_fn, void *a, void *b, void *c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_call_split( "line_user", ap, 
		image, NULL, x1, y1, x2, y2, plot_fn, a, b, c );
	va_end( ap );

	return( result );
}
