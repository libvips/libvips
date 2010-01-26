/* VIPS image class.
 *
 * 7/7/09
 * 	- from vips.h
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

#ifndef IM_IMAGE_H
#define IM_IMAGE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Needed for 'unused' below. Remove this when we remove that.
 */
#include <time.h>

/* If you read MSB first, you get these two values.  
 * intel order: byte 0 = b6 
 * SPARC order: byte 0 = 08
 */
#define IM_MAGIC_INTEL (0xb6a6f208U)
#define IM_MAGIC_SPARC (0x08f2a6b6U)

/* Demand style from im_generate(). See im_demand_hint().
 */
typedef enum {
	IM_SMALLTILE,	
	IM_FATSTRIP,
	IM_THINSTRIP,
	IM_ANY			
} VipsDemandStyle;

typedef enum {
	IM_TYPE_MULTIBAND = 0,
	IM_TYPE_B_W = 1,
	IM_TYPE_HISTOGRAM = 10,
	IM_TYPE_FOURIER = 24,
	IM_TYPE_XYZ = 12,
	IM_TYPE_LAB = 13,
	IM_TYPE_CMYK = 15,
	IM_TYPE_LABQ = 16,
	IM_TYPE_RGB = 17,
	IM_TYPE_UCS = 18,
	IM_TYPE_LCH = 19,
	IM_TYPE_LABS = 21,
	IM_TYPE_sRGB = 22,
	IM_TYPE_YXY = 23,
	IM_TYPE_RGB16 = 25,
	IM_TYPE_GREY16 = 26
} VipsType;

typedef enum {
	IM_BANDFMT_NOTSET = -1,
	IM_BANDFMT_UCHAR = 0,
	IM_BANDFMT_CHAR = 1,
	IM_BANDFMT_USHORT = 2,
	IM_BANDFMT_SHORT = 3,
	IM_BANDFMT_UINT = 4,
	IM_BANDFMT_INT = 5,
	IM_BANDFMT_FLOAT = 6,
	IM_BANDFMT_COMPLEX = 7,
	IM_BANDFMT_DOUBLE = 8,
	IM_BANDFMT_DPCOMPLEX = 9
} VipsBandFmt;

typedef enum {
	IM_CODING_NONE = 0,
	IM_CODING_LABQ = 2,
	IM_CODING_RAD = 6
} VipsCoding;

/* Struct we keep a record of execution time in. Passed to eval callback, so
 * it can assess progress.
 *
 * The 'unused' field is there for binary compatibility, remove this when we
 * break ABI. Though, at least on windows, sizeof(time_t) can vary with
 * compiler flags, so we might break ABI anyway. Remove the #include <time.h>
 * when we remove this.
 */
typedef struct {
	/*< private >*/
	struct _VipsImage *im;	/* Image we are part of */
	time_t unused;		/* FIXME ... for binary compatibility */
	/*< public >*/
	int run;		/* Time we have been running */
	int eta;		/* Estimated seconds of computation left */
	gint64 tpels;		/* Number of pels we expect to calculate */
	gint64 npels;		/* Number of pels calculated so far */
	int percent;		/* Percent complete */
	GTimer *start;		/* Start time */
} VipsProgress;

typedef struct _VipsImage {
	/*< public >*/
	/* Fields from file header.
	 */
	int Xsize;		/* image width, in pixels */
	int Ysize;		/* image height, in pixels */
	int Bands;		/* number of image bands */
	/*< private >*/
	/* No longer used.
	 */
	int Bbits;		/* was number of bits in this format */
	/*< public >*/
	VipsBandFmt BandFmt;	/* #VipsBandFmt describing the pixel format */
	VipsCoding Coding;	/* #VipsCoding describing the pixel coding */
	VipsType Type;		/* #VipsType hinting at pixel interpretation */
	float Xres;		/* horizontal pixels per millimetre */
	float Yres;		/* vertical pixels per millimetre */
	/*< private >*/
	/* No longer used.
	 */
	int Length;
	short Compression;
	short Level;
	/*< public >*/
	int Xoffset;		/* image origin hint */
	int Yoffset;		/* image origin hint */

	/* Derived fields that user can fiddle with.
	 */
	/*< private >*/
	char *Hist;		/* don't use ... call im_history_get() */
	/*< public >*/
	char *filename;		/* pointer to copy of filename */
	char *data;		/* start of image data for WIO */
	VipsProgress *time;	/* evaluation progress */
	int kill;		/* set to non-zero to block partial eval */

	/*< private >*/
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
	VipsDemandStyle dhint;	/* demand style hint */

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
	 *
	 * Parents are later in the tree, so it's child1 + child2 -> parent,
	 * for example. On im_invalidate(), we dispose the caches on all
	 * parents of an image.
	 *
	 * See also hint_set below.
	 */
	GSList *parents;
	GSList *children;
	int serial;

	/* Keep a list of recounted GValue strings so we can share hist
	 * efficiently.
	 */
	GSList *history_list;

	/* The VipsImage (if any) we should signal eval progress on.
	 */
	struct _VipsImage *progress;

	/* Some more callbacks. 
	 */
	GSList *evalstartfns; 	/* list of start eval callbacks */
	GSList *preclosefns; 	/* list of pre-close callbacks */
	GSList *invalidatefns; 	/* list of invalidate callbacks */

	/* Record the file length here. We use this to stop ourselves mapping
	 * things beyond the end of the file in the case that the file has
	 * been truncated.
	 *
	 * gint64 so that we can guarantee to work even on systems with
	 * strange ideas about large files.
	 */
	gint64 file_length;

	/* Set this when im_demand_hint_array() is called, and check in any
	 * operation that will demand pixels from the image.
	 *
	 * We use im_demand_hint_array() to build the tree of parent/child
	 * relationships, so it's a mandatory thing.
	 */
	gboolean hint_set;

	/* Post-close callbacks happen on finalize. Eg. deleting the file
	 * associated with this temp image.
	 */
	GSList *postclosefns; 	

	/* Written callbacks are triggered when an image has been written to. 
	 * Used by eg. im_open("x.jpg", "w") to do the final write to jpeg.
	 */
	GSList *writtenfns; 	
} VipsImage;

extern const size_t im__sizeof_bandfmt[];

/* Pixel address calculation macros.
 */
#define IM_IMAGE_SIZEOF_ELEMENT(I) \
	(im__sizeof_bandfmt[(I)->BandFmt])
#define IM_IMAGE_SIZEOF_PEL(I) \
	(IM_IMAGE_SIZEOF_ELEMENT(I) * (I)->Bands)
#define IM_IMAGE_SIZEOF_LINE(I) \
	(IM_IMAGE_SIZEOF_PEL(I) * (I)->Xsize)
#define IM_IMAGE_N_ELEMENTS(I) \
	((I)->Bands * (I)->Xsize)

/* If DEBUG is defined, add bounds checking.
 */
#ifdef DEBUG
#define IM_IMAGE_ADDR(I,X,Y) \
	( ((X) >= 0 && (X) < (I)->Xsize && \
	   (Y) >= 0 && (Y) < (I)->Ysize) ? \
	     ((I)->data + \
	       (Y) * IM_IMAGE_SIZEOF_LINE(I) + \
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

int im_init_world( const char *argv0 );
GOptionGroup *im_get_option_group( void );

const char *im_version_string( void );
int im_version( int flag );

const char *im_guess_prefix( const char *, const char * );
const char *im_guess_libdir( const char *, const char * );

VipsImage *im_open( const char *filename, const char *mode );

#define im_open_local( IM, NAME, MODE ) \
	((IMAGE *) im_local( (IM), \
		(im_construct_fn) im_open, (im_callback_fn) im_close, \
		(void *) (NAME), (void *) (MODE), NULL ))


/* Strange double cast stops bogus warnings from gcc 4.1
 */
#define im_open_local_array( IM, OUT, N, NAME, MODE ) \
	(im_local_array( (IM), (void **)((void*)(OUT)), (N),\
		(im_construct_fn) im_open, (im_callback_fn) im_close, \
		(void *) (NAME), (void *) (MODE), NULL ))

int im_close( VipsImage *im );

void im_invalidate( VipsImage *im );

void im_initdesc( VipsImage *image, 
	int xsize, int ysize, int bands, int bandbits, 
	VipsBandFmt bandfmt, VipsCoding coding, VipsType type, 
	float xres, float yres,
	int xo, int yo );

int im_cp_desc( VipsImage *out, VipsImage *in );
int im_cp_descv( VipsImage *out, VipsImage *in1, ... )
	__attribute__((sentinel));
int im_cp_desc_array( VipsImage *out, VipsImage *in[] );

VipsImage *im_binfile( const char *name, 
	int xsize, int ysize, int bands, int offset );
VipsImage *im_image( void *buffer, 
	int width, int height, int bands, VipsBandFmt bandfmt );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_IMAGE_H*/
