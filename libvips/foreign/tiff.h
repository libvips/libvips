/* common defs for tiff read/write
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

#ifndef VIPS_TIFF_H
#define VIPS_TIFF_H

#include <tiffio.h>

/* Aperio TIFFs (svs) use these compression types for jp2k-compressed tiles.
 */
#define JP2K_YCC (33003)
#define JP2K_RGB (33005)

/* Bioformats uses this tag for jp2k compressed tiles.
 */
#define JP2K_LOSSY (33004)

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

typedef int (*VipsTiffErrorHandler)(TIFF *tiff, void* user_data,
	const char *module, const char *fmt, va_list ap);

TIFF *vips__tiff_openin_source(VipsSource *source,
	VipsTiffErrorHandler error_fn, VipsTiffErrorHandler warning_fn,
	void *user_data, gboolean unlimited);

TIFF *vips__tiff_openout(const char *path, gboolean bigtiff);
TIFF *vips__tiff_openout_target(VipsTarget *target, gboolean bigtiff,
	VipsTiffErrorHandler error_fn, VipsTiffErrorHandler warning_fn,
	void *user_data);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_TIFF_H*/
