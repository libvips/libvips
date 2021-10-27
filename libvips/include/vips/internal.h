/* Declarations only used internally to vips. See private.h for declarations
 * which are not public, but which have to be publically visible.
 *
 * 11/9/06
 *	- cut from proto.h
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

#ifndef VIPS_INTERNAL_H
#define VIPS_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Try to make an O_BINARY and O_NOINHERIT ... sometimes need the leading '_'.
 */
#if defined(G_PLATFORM_WIN32) || defined(G_WITH_CYGWIN)
# ifndef O_BINARY
#  ifdef _O_BINARY
#   define O_BINARY _O_BINARY
#  endif /*_O_BINARY*/
# endif /*!O_BINARY*/
# ifndef O_NOINHERIT
#  ifdef _O_NOINHERIT
#   define O_NOINHERIT _O_NOINHERIT
#  endif /*_O_NOINHERIT*/
# endif /*!O_NOINHERIT*/
#endif /*defined(G_PLATFORM_WIN32) || defined(G_WITH_CYGWIN)*/

/* If we have O_BINARY, add it to a mode flags set.
 */
#ifdef O_BINARY
# define BINARYIZE(M) ((M) | O_BINARY)
#else /*!O_BINARY*/
# define BINARYIZE(M) (M)
#endif /*O_BINARY*/

/* If we have O_CLOEXEC or O_NOINHERIT, add it to a mode flags set.
 */
#ifdef O_CLOEXEC
# define CLOEXEC(M) ((M) | O_CLOEXEC)
#elif defined(O_NOINHERIT)
# define CLOEXEC(M) ((M) | O_NOINHERIT)
#else /*!O_CLOEXEC && !O_NOINHERIT*/
# define CLOEXEC(M) (M)
#endif /*O_CLOEXEC*/

/* << on an int is undefined in C if the int is negative. Imagine a machine
 * that uses 1s complement, for example.
 *
 * Fuzzers find and warn about this, so we must use this macro instead. Cast
 * to uint, shift, and cast back.
 */
#define VIPS_LSHIFT_INT( I, N ) ((int) ((unsigned int) (I) << (N)))

/* What we store in the Meta hash table. We can't just use GHashTable's 
 * key/value pairs, since we need to iterate over meta in Meta_traverse order.
 *
 * We don't refcount at this level ... large meta values are refcounted by
 * their GValue implementation, see eg. MetaArea.
 */
typedef struct _VipsMeta {
	VipsImage *im;

	char *name;			/* strdup() of field name */
	GValue value;			/* copy of value */
} VipsMeta;

int vips__exif_parse( VipsImage *image );
int vips__exif_update( VipsImage *image );

void vips_check_init( void );

void vips__meta_init_types( void );
void vips__meta_destroy( VipsImage *im );
int vips__meta_cp( VipsImage *, const VipsImage * );

/* Default tile geometry.
 */
extern int vips__tile_width;
extern int vips__tile_height;
extern int vips__fatstrip_height;
extern int vips__thinstrip_height;

/* Default n threads.
 */
extern int vips__concurrency;

/* abort() on any error.
 */
extern int vips__fatal;

/* Enable leak check.
 */
extern int vips__leak;

/* Give progress feedback.
 */
extern int vips__progress;

/* Leak check on exit.
 */
extern int vips__leak;

/* Show info messages. Handy for debugging. 
 */
extern int vips__info;

/* A string giving the image size (in bytes of uncompressed image) above which 
 * we decompress to disc on open. 
 */
extern char *vips__disc_threshold;

extern gboolean vips__cache_dump;
extern gboolean vips__cache_trace;

void vips__threadpool_init( void );
void vips__threadpool_shutdown( void );
int vips__thread_execute( const char *name, GFunc func, gpointer data );

void vips__cache_init( void );

int vips__print_renders( void );
int vips__type_leak( void );
int vips__object_leak( void );

/* iofuncs
 */
int vips__open_image_read( const char *filename );
int vips__open_image_write( const char *filename, gboolean temp );
int vips_image_open_input( VipsImage *image );
int vips_image_open_output( VipsImage *image );

void vips__link_break_all( VipsImage *im );
void *vips__link_map( VipsImage *image, gboolean upstream, 
	VipsSListMap2Fn fn, void *a, void *b );

gboolean vips__mmap_supported( int fd );
void *vips__mmap( int fd, int writeable, size_t length, gint64 offset );
int vips__munmap( const void *start, size_t length );
int vips_mapfile( VipsImage * );
int vips_mapfilerw( VipsImage * );
int vips_remapfilerw( VipsImage * );

void vips__buffer_init( void );
void vips__buffer_shutdown( void );

void vips__copy_4byte( int swap, unsigned char *to, unsigned char *from );
void vips__copy_2byte( gboolean swap, unsigned char *to, unsigned char *from );

guint32 vips__file_magic( const char *filename );
int vips__has_extension_block( VipsImage *im );
void *vips__read_extension_block( VipsImage *im, int *size );
int vips__write_extension_block( VipsImage *im, void *buf, int size );
int vips__writehist( VipsImage *image );
int vips__read_header_bytes( VipsImage *im, unsigned char *from );
int vips__write_header_bytes( VipsImage *im, unsigned char *to );
int vips__image_meta_copy( VipsImage *dst, const VipsImage *src );

extern GMutex *vips__global_lock;

int vips_image_written( VipsImage *image );
void vips_image_preeval( VipsImage *image );
void vips_image_eval( VipsImage *image, guint64 processed );
void vips_image_posteval( VipsImage *image );
VipsImage *vips_image_new_mode( const char *filename, const char *mode );

int vips__formatalike_vec( VipsImage **in, VipsImage **out, int n );
int vips__sizealike_vec( VipsImage **in, VipsImage **out, int n );
int vips__bandup( const char *domain, VipsImage *in, VipsImage **out, int n );
int vips__bandalike_vec( const char *domain, 
	VipsImage **in, VipsImage **out, int n, int base_bands );

int vips__formatalike( VipsImage *in1, VipsImage *in2, 
	VipsImage **out1, VipsImage **out2 );
int vips__sizealike( VipsImage *in1, VipsImage *in2, 
	VipsImage **out1, VipsImage **out2 );
int vips__bandalike( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage **out1, VipsImage **out2 );

/* draw
 */
VipsPel *vips__vector_to_pels( const char *domain, 
	int bands, VipsBandFormat format, VipsCoding coding, 
	double *real, double *imag, int n );
VipsPel *vips__vector_to_ink( const char *domain, 
	VipsImage *im, double *real, double *imag, int n );

int vips__draw_flood_direct( VipsImage *image, VipsImage *test, 
	int serial, int x, int y );
int vips__draw_mask_direct( VipsImage *image, VipsImage *mask, 
	VipsPel *ink, int x, int y ); 

typedef void (*VipsDrawPoint)( VipsImage *image, 
	int x, int y, void *client ); 
typedef void (*VipsDrawScanline)( VipsImage *image, 
	int y, int x1, int x2, int quadrant, void *client );

void vips__draw_line_direct( VipsImage *image, int x1, int y1, int x2, int y2,
	VipsDrawPoint draw_point, void *client );
void vips__draw_circle_direct( VipsImage *image, int cx, int cy, int r,
	VipsDrawScanline draw_scanline, void *client );

int vips__insert_just_one( VipsRegion *out, VipsRegion *in, int x, int y );
int vips__insert_paste_region( VipsRegion *out, VipsRegion *in, VipsRect *pos );

/* Register base vips interpolators, called during startup.
 */
void vips__interpolate_init( void );

/* Start up various packages.
 */
void vips_arithmetic_operation_init( void );
void vips_conversion_operation_init( void );
void vips_resample_operation_init( void );
void vips_foreign_operation_init( void );
void vips_colour_operation_init( void );
void vips_histogram_operation_init( void );
void vips_freqfilt_operation_init( void );
void vips_create_operation_init( void );
void vips_morphology_operation_init( void );
void vips_convolution_operation_init( void );
void vips_draw_operation_init( void );
void vips_mosaicing_operation_init( void );
void vips_cimg_operation_init( void );

guint64 vips__parse_size( const char *size_string );
int vips__substitute( char *buf, size_t len, char *sub );

int vips_check_coding_labq( const char *domain, VipsImage *im );
int vips_check_coding_rad( const char *domain, VipsImage *im );
int vips_check_bands_3ormore( const char *domain, VipsImage *im );

int vips__byteswap_bool( VipsImage *in, VipsImage **out, gboolean swap );

char *vips__xml_properties( VipsImage *image );

void vips__premultiplied_bgra2rgba( guint32 * restrict p, int n );
void vips__bgra2rgba( guint32 * restrict p, int n );
void vips__Lab2LabQ_vec( VipsPel *out, float *in, int width );
void vips__LabQ2Lab_vec( float *out, VipsPel *in, int width );

#ifdef DEBUG_LEAK
extern GQuark vips__image_pixels_quark;
#endif /*DEBUG_LEAK*/

/* With DEBUG_LEAK, hang one of these off each image and count pixels 
 * calculated.
 */
typedef struct _VipsImagePixels {
	const char *nickname; 
	gint64 tpels;		/* Number of pels we expect to calculate */
	gint64 npels;		/* Number of pels calculated so far */
} VipsImagePixels;

int vips__foreign_convert_saveable( VipsImage *in, VipsImage **ready,
	VipsSaveable saveable, VipsBandFormat *format, VipsCoding *coding,
	VipsArrayDouble *background );

int vips_foreign_load( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_foreign_save( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));

int vips__image_intize( VipsImage *in, VipsImage **out );

void vips__reorder_init( void );
int vips__reorder_set_input( VipsImage *image, VipsImage **in );
void vips__reorder_clear( VipsImage *image );

/* Window manager API.
 */
VipsWindow *vips_window_take( VipsWindow *window, 
	VipsImage *im, int top, int height );

int vips__profile_set( VipsImage *image, const char *name );

int vips__lrmosaic( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int bandno,
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth );

int vips__tbmosaic( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int bandno,
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth );

int vips__correl( VipsImage *ref, VipsImage *sec, 
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	double *correlation, int *x, int *y );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_INTERNAL_H*/
