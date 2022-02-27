/* magick as a dynamically loadable module
 *
 * 21/4/21 kleisauke
 * 	- initial
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

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

#if (defined(HAVE_MAGICK6) || defined (HAVE_MAGICK7)) && defined(MAGICK_MODULE)

/* This is called on module load.
 */
G_MODULE_EXPORT const gchar *
g_module_check_init( GModule *module )
{
#ifdef DEBUG
	printf( "vips_magick: module init\n" ); 
#endif /*DEBUG*/

	extern GType vips_foreign_load_magick_file_get_type( void ); 
	extern GType vips_foreign_load_magick_buffer_get_type( void ); 
	extern GType vips_foreign_load_magick7_file_get_type( void ); 
	extern GType vips_foreign_load_magick7_buffer_get_type( void ); 
	extern GType vips_foreign_save_magick_file_get_type( void );
	extern GType vips_foreign_save_magick_bmp_file_get_type( void );
	extern GType vips_foreign_save_magick_buffer_get_type( void );
	extern GType vips_foreign_save_magick_bmp_buffer_get_type( void );

#ifdef ENABLE_MAGICKLOAD
#ifdef HAVE_MAGICK6
	vips_foreign_load_magick_file_get_type();
	vips_foreign_load_magick_buffer_get_type();
#endif /*HAVE_MAGICK6*/

#ifdef HAVE_MAGICK7
	vips_foreign_load_magick7_file_get_type();
	vips_foreign_load_magick7_buffer_get_type();
#endif /*HAVE_MAGICK7*/
#endif /*ENABLE_MAGICKLOAD*/

#ifdef ENABLE_MAGICKSAVE
	vips_foreign_save_magick_file_get_type();
	vips_foreign_save_magick_bmp_file_get_type();
	vips_foreign_save_magick_buffer_get_type();
	vips_foreign_save_magick_bmp_buffer_get_type();
#endif /*ENABLE_MAGICKSAVE*/

	return( NULL );
}

#endif /*(defined(HAVE_MAGICK6) || defined (HAVE_MAGICK7)) && defined(MAGICK_MODULE)*/
