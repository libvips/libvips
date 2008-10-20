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

/* Needed for 'unused' below. Remove this when we remove that.
 */
#include <time.h>

#include <vips/buf.h>
#include <vips/object.h>

#include <vips/version.h>
#include <vips/rect.h>

#define IM_SPARE (8)

/* If you read MSB first, you get these two values. 
 *   intel order: byte 0 = b6
 *   SPARC order: byte 0 = 08
 */
#define IM_MAGIC_INTEL (0xb6a6f208U)
#define IM_MAGIC_SPARC (0x08f2a6b6U)

/* Private to iofuncs: the image size above which we switch from
 * mmap()-whole-image behaviour to mmap()-window, plus window margins.
 */
#define IM__MMAP_LIMIT (1024*1024*30)
#define IM__WINDOW_MARGIN (128)

/* sizeof() a VIPS header on disc.
 */
#define IM_SIZEOF_HEADER (64)

typedef unsigned char PEL;			/* useful datum		*/

/* All these #defines are here for backwards compatibility ... delete them
 * soon. See the bottom of this file for the new names.
 */

/* Only define old, broken names if asked.
 */
#ifdef IM_ENABLE_DEPRECATED

/* On win32, need to override the wingdi defs for these. Yuk!
 */
#ifdef HAVE_WINDOWS_H
#ifdef RGB
#undef RGB
#endif
#ifdef CMYK
#undef CMYK
#endif
#endif /*HAVE_WINDOWS_H*/

/* Bits per Band */
#define BBBYTE		8
#define BBSHORT		16
#define BBINT		32
#define BBFLOAT		32
#define BBCOMPLEX	64	/* complex consisting of two floats */
#define BBDOUBLE	64
#define BBDPCOMPLEX	128	/* complex consisting of two doubles */

/* picture Type */
#define MULTIBAND	0
#define B_W		1
#define LUMINACE	2
#define XRAY		3
#define IR		4
#define YUV		5
#define RED_ONLY	6			/* red channel only	*/
#define GREEN_ONLY	7			/* green channel only	*/
#define BLUE_ONLY	8			/* blue channel only	*/
#define POWER_SPECTRUM	9
#define HISTOGRAM	10
#define FOURIER		24

/* Colour spaces.
 */
#define LUT		11
#define XYZ		12
#define LAB		13
#define CMC		14
#define CMYK		15
#define LABQ		16
#define RGB		17
#define UCS		18
#define LCH		19
#define LABS		21
#define sRGB		22
#define YXY		23

/* BandFmt 
 */
#define FMTNOTSET	-1	
#define FMTUCHAR	0	/* pels interpreted as unsigned chars */
#define FMTCHAR		1	/* pels interpreted as signed chars */
#define FMTUSHORT	2	/* pels interpreted as unsigned shorts */
#define FMTSHORT	3	/* pels interpreted as signed shorts */
#define FMTUINT		4	/* pels interpreted as unsigned ints */
#define FMTINT		5	/* pels interpreted as signed ints */
#define FMTFLOAT	6	/* pels interpreted as floats */
#define FMTCOMPLEX	7	/* pels interpreted as complex (2 float each) */
#define FMTDOUBLE	8	/* pels interpreted as unsigned double */
#define FMTDPCOMPLEX	9	/* pels interpreted as complex (2 double each)*/

/* Coding type 
 */
#define NOCODING		0
#define COLQUANT		1
#define LABPACK			2
#define LABPACK_COMPRESSED	3
#define RGB_COMPRESSED		4
#define LUM_COMPRESSED		5

/* Compression type 
 */
#define NO_COMPRESSION		0
#define TCSF_COMPRESSION	1
#define JPEG_COMPRESSION	2

#endif /*IM_ENABLE_DEPRECATED*/

/* Types of image descriptor we may have. The type field is advisory only: it
 * does not imply that any fields in IMAGE have valid data.
 */
typedef enum {
	IM_NONE,		/* no type set */
	IM_SETBUF,		/* malloced memory array */
	IM_SETBUF_FOREIGN,	/* memory array, don't free on close */
	IM_OPENIN,		/* input from fd */
	IM_MMAPIN,		/* memory mapped input file */
	IM_MMAPINRW,		/* memory mapped read/write file */
	IM_OPENOUT,		/* output to fd */
	IM_PARTIAL		/* partial image */
} im_desc_type;

/* Demand style from im_generate(). See im_demand_hint().
 */
typedef enum {
	IM_SMALLTILE,	
	IM_FATSTRIP,
	IM_THINSTRIP,
	IM_ANY			/* Not from a disc file, any geometry */
} im_demand_type;

/* What we track for each mmap window. Have a list of these on an openin
 * IMAGE.
 */
typedef struct {
	int ref_count;		/* # of regions referencing us */
	struct im__IMAGE *im;	/* IMAGE we are attached to */

	int top; 		/* Area of image we have mapped, in pixels */
	int height;
	char *data;		/* First pixel of line 'top' */

	PEL *baseaddr;		/* Base of window */
	size_t length;		/* Size of window */
} im_window_t;

/* Struct we keep a record of execution time in. Passed to eval callback, so
 * it can assess progress.
 *
 * The 'unused' field is there for binary compatibility, remove this when we
 * break ABI. Though, at least on windows, sizeof(time_t) can vary with
 * compiler flags, so we might break ABI anyway. Remove the #include <time.h>
 * when we remove this.
 */
typedef struct {
	struct im__IMAGE *im;	/* Image we are part of */
	time_t unused;		/* FIXME ... for binary compatibility */
	int run;		/* Time we have been running */
	int eta;		/* Estimated seconds of computation left */
	gint64 tpels;		/* Number of pels we expect to calculate */
	gint64 npels;		/* Number of pels calculated so far */
	int percent;		/* Percent complete */
	GTimer *start;		/* Start time */
} im_time_t;

/* Image descriptor for subroutine i/o args 
 */
typedef struct im__IMAGE {
	/* Fields from file header.
	 */
	int Xsize;
	int Ysize;
	int Bands;
	int Bbits;
	int BandFmt;
	int Coding;
	int Type;
	float Xres;
	float Yres;
	int Length;
	short Compression;
	short Level;
	int Xoffset;
	int Yoffset;

	/* Derived fields that user can fiddle with.
	 */
	char *Hist;		/* don't use ... call im_history_get() */
	char *filename;		/* pointer to copy of filename */
	char *data;		/* start of image data for WIO */
	im_time_t *time;	/* time struct for eval callback */
	int kill;		/* set to non-zero to block partial eval */

	/* Private fields.
	 */
	im_desc_type dtype;	/* descriptor type */
	int fd;         	/* file descriptor */
	char *baseaddr;     	/* pointer to the start of an mmap file */
	size_t length;		/* size of mmap area */
	GSList *closefns; 	/* list of close callbacks */
	GSList *evalfns; 	/* list of eval callbacks */
	GSList *evalendfns; 	/* list of eval end callbacks */
	int closing;		/* true for this descriptor is closing */
	int close_pending;	/* true for this descriptor is a zombie */
	guint32 magic;		/* magic from header, endian-ness of image */

	/* Partial image stuff. All private! All these fields are initialised 
	 * to NULL and ignored unless set by im_generate() or im_partial().
	 */
	void *(*start)();	/* user-supplied start function */
	int (*generate)();	/* user-supplied generate function */
	int (*stop)();		/* user-supplied stop function */
	void *client1;		/* user arguments */
	void *client2;
	GMutex *sslock;		/* start-stop lock */
	GSList *regions; 	/* list of regions current for this image */
	im_demand_type dhint;	/* demand style hint */

	/* Extra user-defined fields ... see im_meta_get_int() etc.
	 */
	GHashTable *Meta;	/* GhashTable of GValue */
	GSList *Meta_traverse;	/* Traverse order for Meta */

	/* Part of mmap() read ... the sizeof() the header we skip from the
	 * file start. Usually IM_SIZEOF_HEADER, but can be something else
	 * for binary file read.
	 */
	int sizeof_header;

	/* If this is a large disc image, don't map the whole thing, instead
	 * have a set of windows shared between the regions active on the
	 * image. List of im_window_t.
	 */
	GSList *windows;

	/* Parent/child relationships, built from args to im_demand_hint().
	 * We use these to invalidate pixel buffers on im_invalidate(). Use
	 * 'serial' to spot circular dependencies.
	 */
	GSList *parents;
	GSList *children;
	int serial;

	/* Keep a list of recounted GValue strings so we can share hist
	 * efficiently.
	 */
	GSList *history_list;

	/* The IMAGE (if any) we should signal eval progress on.
	 */
	struct im__IMAGE *progress;

	/* Some more callbacks. Appended to IMAGE for binary compatibility.
	 */
	GSList *evalstartfns; 	/* list of start eval callbacks */
	GSList *preclosefns; 	/* list of pre-close callbacks */
	GSList *invalidatefns; 	/* list of invalidate callbacks */
} IMAGE;

/* Only define if IM_ENABLE_DEPRECATED is set.
 */
#ifdef IM_ENABLE_DEPRECATED

/* Macros on IMAGEs.
 *	esize()		sizeof band element
 *	psize()		sizeof pel
 *	lsize()		sizeof scan line
 *	niele()		number of elements in scan line
 */
#define esize(I) ((I)->Bbits >> 3)
#define psize(I) (esize(I)*(I)->Bands)
#define lsize(I) (psize(I)*(I)->Xsize)
#define niele(I) ((I)->Bands*(I)->Xsize)

#endif /*IM_ENABLE_DEPRECATED*/

/* Used to define a region of interest for im_extract() etc.
 */
typedef struct { 
	int xstart;
	int ystart;
	int xsize;
	int ysize;
	int chsel;      /* 1 2 3 or 0, for r g b or all respectively
			 *(channel select)	*/
} IMAGE_BOX;

/* @(#) Definition for structure to hold integer or double masks
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

/* A colour temperature.
 */
typedef struct {
	double X0, Y0, Z0;
} im_colour_temperature;

/* Sensible names for our #defines. Only bother with
 * the ones we actually use. Switch over to defining only these ones at some 
 * point (vips8?).
 */

#define IM_BBITS_BYTE			(8)
#define IM_BBITS_SHORT			(16)
#define IM_BBITS_INT			(32)
#define IM_BBITS_FLOAT			(32)
#define IM_BBITS_COMPLEX		(64)
#define IM_BBITS_DOUBLE			(64)
#define IM_BBITS_DPCOMPLEX		(128)

#define IM_TYPE_MULTIBAND		(0)
#define IM_TYPE_B_W			(1)
#define IM_TYPE_HISTOGRAM		(10)
#define IM_TYPE_FOURIER			(24)
#define IM_TYPE_XYZ			(12)
#define IM_TYPE_LAB			(13)
#define IM_TYPE_CMYK			(15)
#define IM_TYPE_LABQ			(16)
#define IM_TYPE_RGB			(17)
#define IM_TYPE_UCS			(18)
#define IM_TYPE_LCH			(19)
#define IM_TYPE_LABS			(21)
#define IM_TYPE_sRGB			(22)
#define IM_TYPE_YXY			(23)
#define IM_TYPE_RGB16			(25)
#define IM_TYPE_GREY16			(26)

#define IM_BANDFMT_NOTSET		(-1)	
#define IM_BANDFMT_UCHAR		(0)	
#define IM_BANDFMT_CHAR			(1)		
#define IM_BANDFMT_USHORT		(2)	
#define IM_BANDFMT_SHORT		(3)	
#define IM_BANDFMT_UINT			(4)		
#define IM_BANDFMT_INT			(5)		
#define IM_BANDFMT_FLOAT		(6)	
#define IM_BANDFMT_COMPLEX		(7)	
#define IM_BANDFMT_DOUBLE		(8)	
#define IM_BANDFMT_DPCOMPLEX		(9)	

#define IM_CODING_NONE			(0)			
#define IM_CODING_LABQ			(2)				

#define IM_IMAGE_SIZEOF_ELEMENT(I)	((I)->Bbits >> 3)
#define IM_IMAGE_SIZEOF_PEL(I) 	\
	(IM_IMAGE_SIZEOF_ELEMENT(I) * (I)->Bands)
#define IM_IMAGE_SIZEOF_LINE(I) 	(IM_IMAGE_SIZEOF_PEL(I) * (I)->Xsize)
#define IM_IMAGE_N_ELEMENTS(I)		((I)->Bands * (I)->Xsize)

/* If DEBUG is defined, add bounds checking.
 */
#ifdef DEBUG
#define IM_IMAGE_ADDR(I,X,Y) \
	( ((X) >= 0 && (X) < (I)->Xsize && \
	   (Y) >= 0 && (Y) < (I)->Ysize) ? \
	     ((I)->data + (Y) * IM_IMAGE_SIZEOF_LINE(I) + \
	       (X) * IM_IMAGE_SIZEOF_PEL(I)) : \
	     (fprintf( stderr, \
		"IM_IMAGE_ADDR: point out of bounds, " \
		"file \"%s\", line %d\n" \
		"(point x=%d, y=%d\n" \
		" should have been within Rect left=%d, top=%d, " \
		"width=%d, height=%d)\n", \
		__FILE__, __LINE__, \
		(X), (Y), \
		0, 0, \
		(I)->Xsize, \
		(I)->Ysize ), abort(), (char *) NULL) \
	)
#else /*DEBUG*/
#define IM_IMAGE_ADDR(I,X,Y) \
	((I)->data + \
	 (Y) * IM_IMAGE_SIZEOF_LINE(I) + \
	 (X) * IM_IMAGE_SIZEOF_PEL(I))
#endif /*DEBUG*/

#include <vips/proto.h>
#include <vips/colour.h>
/* #include <vips/vector.h> */
#include <vips/format.h>
#include <vips/dispatch.h>
#include <vips/region.h>
#include <vips/interpolate.h>
#include <vips/semaphore.h>
#include <vips/threadgroup.h>
#include <vips/meta.h>
#include <vips/util.h>

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_VIPS_H*/
