/* helper functions for Orc
 *
 * 29/10/10
 * 	- from morph hacking
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
#include <glib/gi18n-lib.h>

#include <stdlib.h>

#include <vips/vips.h>
#include <vips/vector.h>
#include <vips/debug.h>
#include <vips/internal.h>

/* If we are building with -fcf-protection (run-time checking of
 * indirect jumps) then Orc won't work. Make sure it's off.
 *
 * https://gcc.gnu.org/onlinedocs/gcc/\
 * 	Instrumentation-Options.html#index-fcf-protection
 * https://gitlab.freedesktop.org/gstreamer/orc/issues/17
 *
 * orc 0.4.30 and later work with cf-protection.
 */
#ifdef __CET__
#ifndef HAVE_ORC_CF_PROTECTION
#undef HAVE_ORC
#endif
#endif

#ifdef HAVE_ORC
#include <orc/orc.h>
#endif /*HAVE_ORC*/

/* Cleared by the command-line `--vips-novector` switch and the
 * `VIPS_NOVECTOR` env var.
 */
gboolean vips__vector_enabled = TRUE;

void
vips__vector_init(void)
{
#ifdef HAVE_ORC
	orc_init();
#endif /*HAVE_ORC*/

	/* Look for the deprecated IM_NOVECTOR environment variable as well.
	 */
	if (g_getenv("VIPS_NOVECTOR")
#if ENABLE_DEPRECATED
		|| g_getenv("IM_NOVECTOR")
#endif
	)
		vips__vector_enabled = FALSE;
}

gboolean
vips_vector_isenabled(void)
{
#ifdef HAVE_ORC
	return vips__vector_enabled;
#else  /*!HAVE_ORC*/
	return FALSE;
#endif /*HAVE_ORC*/
}

void
vips_vector_set_enabled(gboolean enabled)
{
	vips__vector_enabled = enabled;
}
