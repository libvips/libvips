/* @(#) Header file for Birkbeck/VIPS Image Processing Library
 * Authors: N. Dessipris, K. Martinez, Birkbeck College, London.
 * Sept 94
 *
 * 15/7/96 JC
 * 	- now does C++ extern stuff
 *	- many more protos
 * 15/4/97 JC
 *	- protos split out
 * 4/3/98 JC
 *	- IM_ANY added
 *	- sRGB colourspace added
 * 28/10/98 JC
 *	- VASARI_MAGIC_INTEL and VASARI_MAGIC_SPARC added
 * 29/9/99 JC
 *	- new locks for threading, no more threadgroup stuff in IMAGE
 * 30/11/00 JC
 *	- override RGB/CMYK macros on cygwin
 * 21/9/02 JC
 *	- new Xoffset/Yoffset fields
 *	- rationalized macro names
 * 6/6/05 Markus Wollgarten
 * 	- added Meta header field
 * 31/7/05
 * 	- added meta.h for new metadata API
 * 22/8/05
 * 	- scrapped stupid VAS_HD
 * 30/9/05
 * 	- added sizeof_header field for mmap window read of RAW files
 * 4/10/05
 * 	- now you have to define IM_ENABLE_DEPRECATED to get broken #defined
 * 5/10/05
 * 	- added GNUC attributes
 * 8/5/06
 * 	- added RGB16, GREY16
 * 30/10/06
 * 	- added im_window_t
 * 7/11/07
 * 	- added preclose and evalstart callbacks
 * 	- brought time struct in here
 * 7/3/08
 * 	- MAGIC values should be unsigned
 * 2/7/08
 * 	- added invalidate callbacks
 * 7/8/08
 * 	- include <time.h>, thanks nicola
 * 30/6/09
 * 	- move deprecated stuff to its own header
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_VIPS_H
#define IM_VIPS_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* If we're not using GNU C, elide __attribute__ 
 */
#ifndef __GNUC__
#  ifndef __attribute__
#    define __attribute__(x)  /*NOTHING*/
#  endif
#endif

#include <glib.h>
#include <gmodule.h>
#include <glib-object.h>

#include <vips/buf.h>
#include <vips/object.h>

#include <vips/version.h>
#include <vips/rect.h>

#include <vips/private.h>

/* Argh, these horrible things must go :(
 */

typedef struct im__INTMASK {
	int xsize;
	int ysize;
	int scale;
	int offset;
	int *coeff;
	char *filename;
} INTMASK ;

typedef struct im__DOUBLEMASK {
	int xsize;
	int ysize;
	double scale;
	double offset;
	double *coeff;
	char *filename;
} DOUBLEMASK ;

#include <vips/image.h>
#include <vips/almostdeprecated.h>
#include <vips/callback.h>
#include <vips/error.h>
#include <vips/util.h>
#include <vips/colour.h>
/* #include <vips/vector.h> */
#include <vips/format.h>
#include <vips/dispatch.h>
#include <vips/region.h>
#include <vips/generate.h>
#include <vips/check.h>
#include <vips/interpolate.h>
#include <vips/semaphore.h>
#include <vips/threadgroup.h>

#include <vips/meta.h>
#include <vips/header.h>

#include <vips/proto.h>
#include <vips/arithmetic.h>
#include <vips/boolean.h>
#include <vips/relational.h>

#ifdef IM_ENABLE_DEPRECATED
#include <vips/deprecated.h>
#endif /*IM_ENABLE_DEPRECATED*/

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_VIPS_H*/
