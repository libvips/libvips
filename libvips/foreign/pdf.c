/* Utility functions for the PDF loaders.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

#if defined(HAVE_POPPLER) || defined (HAVE_PDFIUM)

const char *vips__pdf_suffs[] = {
	".pdf",
	NULL
};

gboolean
vips__pdf_is_a_buffer(const void *buf, size_t len)
{
	const char *str = (const char *) buf;

	if (len < 4)
		return FALSE;

	for (size_t i = 0; i < len - 4; i++)
		if (vips_isprefix("%PDF", str + i))
			return TRUE;

	return FALSE;
}

/* PDF v2 allows for offset headers, ie. there may be any number of
 * characters of padding before the "%PDF" file marker. These can be
 * arbitrary printer control characters, whitespace, etc.
 *
 * In practice, the amount of padding is usually small (less than 32
 * bytes).
 *
 * Another strategy is to look for "%EOF" in the final 1k of the file, but of
 * course that won't work well for streamed data.
 */
#define MAX_OFFSET (32)

gboolean
vips__pdf_is_a_file(const char *filename)
{
	unsigned char buf[MAX_OFFSET];

	if (vips__get_bytes(filename, buf, MAX_OFFSET) == MAX_OFFSET &&
		vips__pdf_is_a_buffer(buf, MAX_OFFSET))
		return TRUE;

	return FALSE;
}

gboolean
vips__pdf_is_a_source(VipsSource *source)
{
	const unsigned char *p;

	return (p = vips_source_sniff(source, MAX_OFFSET)) &&
		vips__pdf_is_a_buffer(p, MAX_OFFSET);
}

#endif /*defined(HAVE_POPPLER) || defined (HAVE_PDFIUM)*/
