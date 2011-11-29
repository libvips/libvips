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

#ifndef VIPS_VIPS_H
#define VIPS_VIPS_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <glib.h>
#include <glib/gstdio.h>
#include <gmodule.h>
#include <glib-object.h>

/* If we're being parsed by SWIG, remove gcc attributes.
 */
#ifdef SWIG
#  ifndef __attribute__
#    define __attribute__(x)  /*NOTHING*/
#  endif
#endif /*SWIG*/

#include <vips/buf.h>
#include <vips/util.h>
#include <vips/object.h>
#include <vips/type.h>

#include <vips/version.h>
#include <vips/rect.h>

#include <vips/private.h>

#include <vips/mask.h>
#include <vips/image.h>
#include <vips/memory.h>
#include <vips/error.h>
#include <vips/format.h>
#include <vips/region.h>
#include <vips/generate.h>
#include <vips/interpolate.h>
#include <vips/semaphore.h>
#include <vips/threadpool.h>
#include <vips/header.h>
#include <vips/operation.h>
#include <vips/foreign.h>

#include <vips/enumtypes.h>

#include <vips/arithmetic.h>
#include <vips/relational.h>
#include <vips/conversion.h>
#include <vips/convolution.h>
#include <vips/morphology.h>
#include <vips/mosaicing.h>
#include <vips/histograms_lut.h>
#include <vips/freq_filt.h>
#include <vips/resample.h>
#include <vips/colour.h>
#include <vips/disp.h>
#include <vips/inplace.h>
#include <vips/other.h>
#include <vips/video.h>
#include <vips/cimg_funcs.h>

#ifndef VIPS_DISABLE_VIPS7COMPAT
#include <vips/vips7compat.h>
#endif /*VIPS_DISABLE_VIPS7COMPAT*/

#ifdef VIPS_ENABLE_DEPRECATED
#include <vips/deprecated.h>
#endif /*VIPS_ENABLE_DEPRECATED*/

#include <vips/almostdeprecated.h>
#include <vips/dispatch.h>

const char *vips_get_argv0( void );
int vips_init( const char *argv0 );
void vips_check_init( void );
void vips_shutdown( void );
GOptionGroup *vips_get_option_group( void );

const char *vips_version_string( void );
int vips_version( int flag );

const char *vips_guess_prefix( const char *argv0, const char *env_name );
const char *vips_guess_libdir( const char *argv0, const char *env_name );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_VIPS_H*/
