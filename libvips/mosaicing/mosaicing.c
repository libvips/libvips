/* base class for all mosaicing operations
 *
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

/* Define for debug output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_mosaicing_operation_init(void)
{
	extern GType vips_merge_get_type(void);
	extern GType vips_mosaic_get_type(void);
	extern GType vips_mosaic1_get_type(void);
	extern GType vips_match_get_type(void);
	extern GType vips_globalbalance_get_type(void);
	extern GType vips_matrixinvert_get_type(void);
	extern GType vips_matrixmultiply_get_type(void);
	extern GType vips_remosaic_get_type(void);

	vips_merge_get_type();
	vips_mosaic_get_type();
	vips_mosaic1_get_type();
	vips_matrixinvert_get_type();
	vips_matrixmultiply_get_type();
	vips_match_get_type();
	vips_globalbalance_get_type();
	vips_remosaic_get_type();
}
