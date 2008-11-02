/* @(#) Convert a signed or unsigned, char or short or int image into unsigned
 * @(#) char very quickly, by discarding the lower order bits.  Signed values
 * @(#) are converted to unsigned by adding 128.
 * @(#)
 * @(#) int
 * @(#) im_msb(
 * @(#)   IMAGE *in,
 * @(#)   IMAGE *out
 * @(#) );
 * @(#)
 * @(#) As above, but also discard all but the specified band:
 * @(#)
 * @(#) int
 * @(#) im_msb(
 * @(#)   IMAGE *in,
 * @(#)   IMAGE *out,
 * @(#)   int band
 * @(#) );
 *
 * Copyright: 2006, The Nottingham Trent University
 *
 * Author: Tom Vajzovic
 *
 * Written on: 2006-03-13
 * 27/9/06
 * 	- removed extra im_free() in im_copy() fallback
 * 4/10/06
 * 	- removed warning on uchar fallback: it happens a lot with nip2 and
 * 	  isn't very serious
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

/** HEADERS **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H */
#include <vips/intl.h>

#include <stdlib.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC */

/** MACROS **/
/* BAND FORMAT TESTS */

#define SIZEOF_BAND(band_fmt) (                                       \
     ( IM_BANDFMT_UCHAR == (band_fmt) ) ? sizeof(unsigned char)       \
 :   ( IM_BANDFMT_CHAR  == (band_fmt) ) ? sizeof(signed char)         \
 :  ( IM_BANDFMT_USHORT == (band_fmt) ) ? sizeof(unsigned short int)  \
 :   ( IM_BANDFMT_SHORT == (band_fmt) ) ? sizeof(signed short int)    \
 :    ( IM_BANDFMT_UINT == (band_fmt) ) ? sizeof(unsigned int)        \
 :     ( IM_BANDFMT_INT == (band_fmt) ) ? sizeof(signed int)          \
 :   ( IM_BANDFMT_FLOAT == (band_fmt) ) ? sizeof(float)               \
 :  ( IM_BANDFMT_DOUBLE == (band_fmt) ) ? sizeof(double)              \
 : ( IM_BANDFMT_COMPLEX == (band_fmt) ) ? ( 2 * sizeof(float) )       \
 :                                        ( 2 * sizeof(double) ) )

#define BANDFMT_SHORT_CHAR(band_fmt)  (  \
       IM_BANDFMT_SHORT == (band_fmt)    \
  ||  IM_BANDFMT_USHORT == (band_fmt)    \
  ||    IM_BANDFMT_CHAR == (band_fmt)    \
  ||   IM_BANDFMT_UCHAR == (band_fmt) )

#define BANDFMT_ANY_INT(band_fmt)    (  \
         IM_BANDFMT_INT == (band_fmt)   \
  ||    IM_BANDFMT_UINT == (band_fmt)   \
  ||     BANDFMT_SHORT_CHAR(band_fmt) )

#define BANDFMT_UNSIGNED(band_fmt)  (   \
        IM_BANDFMT_UINT == (band_fmt)   \
  ||  IM_BANDFMT_USHORT == (band_fmt)   \
  ||   IM_BANDFMT_UCHAR == (band_fmt) )

/* IMAGE TESTS */

#define IM_ANY_INT(im)      BANDFMT_ANY_INT((im)-> BandFmt)
#define IM_UNSIGNED(im)     BANDFMT_UNSIGNED((im)-> BandFmt)
#define IM_UNCODED(im)      ( IM_CODING_NONE == (im)-> Coding )

/** LOCAL FUNCTIONS DECLARATIONS **/
static void byte_select (unsigned char *in, unsigned char *out, int n,
			 size_t * params);
static void byte_select_flip (unsigned char *in, unsigned char *out, int n,
			      size_t * params);
static void msb_labq (unsigned char *in, unsigned char *out, int n);

/** EXPORTED FUNCTIONS **/

int
im_msb (IMAGE * in, IMAGE * out)
{
#define FUNCTION_NAME "im_msb"

  size_t *params;
  im_wrapone_fn func;

#define index   (params[0])
#define width   (params[1])
#define repeat  (params[2])

  if (im_piocheck (in, out))
    return -1;

  /* Stops a used-before-set warning.
   */
  params = NULL;

  if (IM_UNCODED (in))
    {

      if (!IM_ANY_INT (in))
	{
	  im_error (FUNCTION_NAME, "%s", _("char, short or int only"));
	  return -1;
	}

      params = IM_ARRAY (out, 3, size_t);

      if (!params)
	return -1;

      width = SIZEOF_BAND (in->BandFmt);

#if G_BYTE_ORDER == G_BIG_ENDIAN
      index = 0;
#else
      index = width - 1;
#endif

      repeat = in->Bands;

      if (IM_UNSIGNED (in))
	func = (im_wrapone_fn) byte_select;
      else
	func = (im_wrapone_fn) byte_select_flip;

      if (1 == width && (im_wrapone_fn) byte_select == func)
	{
	  return im_copy (in, out);
	}
    }

  else if (IM_CODING_LABQ == in->Coding)

    func = (im_wrapone_fn) msb_labq;

  else
    {
      im_error (FUNCTION_NAME, "%s", _("unknown coding"));
      return -1;
    }

  if (im_cp_desc (out, in))
    return -1;

  out->Bbits = sizeof (unsigned char) << 3;
  out->BandFmt = IM_BANDFMT_UCHAR;
  out->Coding = IM_CODING_NONE;

  return im_wrapone (in, out, func, (void *) params, NULL);

#undef index
#undef width
#undef repeat

#undef FUNCTION_NAME
}

int
im_msb_band (IMAGE * in, IMAGE * out, int band)
{
#define FUNCTION_NAME "im_msb_band"

  size_t *params;
  im_wrapone_fn func;

#define index   (params[0])
#define width   (params[1])
#define repeat  (params[2])

  if (band < 0)
    {
      im_error (FUNCTION_NAME, "%s", _("bad arguments"));
      return -1;
    }

  if (im_piocheck (in, out))
    return -1;

  params = IM_ARRAY (out, 3, size_t);

  if (!params)
    return -1;

  if (IM_UNCODED (in))
    {

      if (!IM_ANY_INT (in))
	{
	  im_error (FUNCTION_NAME, "%s", _("char, short or int only"));
	  return -1;
	}

      if (band >= in->Bands)
	{
	  im_error (FUNCTION_NAME,
	    "%s", _("image does not have that many bands"));
	  return -1;
	}

      width = SIZEOF_BAND (in->BandFmt);

#if G_BYTE_ORDER == G_BIG_ENDIAN
      index = width * band;
#else
      index = (width * (band + 1)) - 1;
#endif

      width *= in->Bands;
      repeat = 1;

      if (IM_UNSIGNED (in))
	func = (im_wrapone_fn) byte_select;
      else
	func = (im_wrapone_fn) byte_select_flip;
    }

  else if (IM_CODING_LABQ == in->Coding)
    {

      if (band > 2)
	{
	  im_error (FUNCTION_NAME, 
	    "%s", _("image does not have that many bands"));
	  return -1;
	}
      width = 4;
      repeat = 1;
      index = band;

      if (band)
	func = (im_wrapone_fn) byte_select_flip;
      else
	func = (im_wrapone_fn) byte_select;
    }
  else
    {
      im_error (FUNCTION_NAME, "%s", _("unknown coding"));
      return -1;
    }

  if (im_cp_desc (out, in))
    return -1;

  out->Bands = 1;
  out->Bbits = sizeof (unsigned char) << 3;
  out->BandFmt = IM_BANDFMT_UCHAR;
  out->Coding = IM_CODING_NONE;

  return im_wrapone (in, out, func, (void *) params, NULL);

#undef index
#undef width
#undef repeat

#undef FUNCTION_NAME
}

/** LOCAL FUNCTIONS DEFINITIONS **/
static void
byte_select (unsigned char *in, unsigned char *out, int n, size_t * params)
{
#define index   (params[0])
#define width   (params[1])
#define repeat  (params[2])

  unsigned char *stop = out + n * repeat;

  for (in += index; out < stop; in += width, ++out)
    *out = *in;

#undef index
#undef width
#undef repeat
}

static void
byte_select_flip (unsigned char *in, unsigned char *out, int n,
		  size_t * params)
{
#define index   (params[0])
#define width   (params[1])
#define repeat  (params[2])

  unsigned char *stop = out + n * repeat;

  for (in += index; out < stop; in += width, ++out)
    *out = 0x80 ^ *in;

#undef index
#undef width
#undef repeat
}

static void
msb_labq (unsigned char *in, unsigned char *out, int n)
{
  unsigned char *stop = in + (n << 2);

  for (; in < stop; in += 4, out += 3)
    {
      out[0] = in[0];
      out[1] = 0x80 ^ in[1];
      out[2] = 0x80 ^ in[2];
    }
}
