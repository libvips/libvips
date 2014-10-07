/* pass images through gmic
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
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
#include <vips/intl.h>

#include <vips/vips.h>

/** 
 * SECTION: cimg
 * @short_description: pass images through the gmic interpreter
 * @see_also: <link linkend="libvips-boolean">boolean</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * Pass images through the gmic interpreter. 
 */

/**
 * vips_gmic:
 * @in: (array length=n) (transfer none): array of input images
 * @out: output image
 * @n: number of input images
 * @padding: overlap tiles by this much
 * @x_scale: 
 * @y_scale: 
 * @command: command to execute
 *
 * Returns: 0 on success, -1 on failure. 
 */
int
vips_gmic( VipsImage **in, VipsImage **out, int n, 
	int padding, double x_scale, double y_scale, const char *command, ... )
{
	VipsArrayImage *array; 
	va_list ap;
	int result;

	array = vips_array_image_new( in, n ); 
	va_start( ap, command );
	result = vips_call_split( "gmic", ap, array, out, 
		padding, x_scale, y_scale, command );
	va_end( ap );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_cimg_operation_init( void )
{
#ifdef HAVE_GMIC
	extern GType vips_gmic_get_type( void ); 
#endif /*HAVE_GMIC*/

#ifdef HAVE_GMIC
	vips_gmic_get_type(); 
#endif /*HAVE_GMIC*/
}
