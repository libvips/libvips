/* Prototypes for internal VIPS functions.
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_INTERNAL_H
#define IM_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Default tile geometry.
 */
extern int im__tile_width;
extern int im__tile_height;
extern int im__fatstrip_height;
extern int im__thinstrip_height;

/* Default n threads.
 */
extern int im__concurrency;

/* Give progress feedback.
 */
extern int im__progress;

typedef int (*im__fftproc_fn)( IMAGE *, IMAGE *, IMAGE * );

/* iofuncs
 */
void im__read_4byte( int msb_first, unsigned char *to, unsigned char **from );
void im__read_2byte( int msb_first, unsigned char *to, unsigned char **from );
void im__write_4byte( unsigned char **to, unsigned char *from );
void im__write_2byte( unsigned char **to, unsigned char *from );

int im__read_header_bytes( IMAGE *im, unsigned char *from );
int im__write_header_bytes( IMAGE *im, unsigned char *to );
int im__has_extension_block( IMAGE *im );
void *im__read_extension_block( IMAGE *im, int *size );
int im__readhist( IMAGE *image );
int im__write_extension_block( IMAGE *im, void *buf, int size );
int im__writehist( IMAGE *image );
int im__start_eval( IMAGE *im );
int im__handle_eval( IMAGE *im, int w, int h );
int im__end_eval( IMAGE *im );
int im__time_destroy( IMAGE *im );

extern int im__read_test;
extern int im__mmap_limit;
extern GMutex *im__global_lock;

typedef enum {
	IM__RGB,	/* 1 or 3 bands (like PPM) */
	IM__RGBA,	/* 1, 2, 3 or 4 bands (like PNG) */
	IM__RGB_CMYK	/* 1, 3 or 4 bands (like JPEG) */
} im__saveable_t;

IMAGE *im__convert_saveable( IMAGE *in, im__saveable_t saveable );

void im__link_make( IMAGE *parent, IMAGE *child );
void im__link_break_all( IMAGE *im );
void *im__link_map( IMAGE *im, VSListMap2Fn fn, void *a, void *b );

GValue *im__gvalue_ref_string_new( const char *text );
void im__gslist_gvalue_free( GSList *list );
GSList *im__gslist_gvalue_copy( const GSList *list );
GSList *im__gslist_gvalue_merge( GSList *a, const GSList *b );
char *im__gslist_gvalue_get( const GSList *list );

void im__buffer_init( void );

int im__cast_and_call();
int im__read_header( IMAGE *image );
int im__test_kill( IMAGE *im );
void *im__mmap( int fd, int writeable, size_t length, gint64 offset );
int im__munmap( void *start, size_t length );
int im__write( int, const void *, size_t );
int im__open_image_file( const char *filename );
gint64 im__image_pixel_length( IMAGE *im );
void im__change_suffix( const char *name, char *out, int mx,
        const char *new_suff, const char **olds, int nolds );
void im__print_all( void );
void im__print_one( int );
int im__trigger_callbacks( GSList *cblist );
int im__close( IMAGE * );
int im__handle_eval( IMAGE *im, int w, int h );
int im__create_int_luts( int *, int, int **, int **, int * );
int im__create_double_luts( double *, int, double **, double **, int * );
int im__fft_sp( float *rvec, float *ivec, int logrows, int logcols );
int im__fftproc( IMAGE *dummy, IMAGE *in, IMAGE *out, im__fftproc_fn fn );
int im__mean_std_double_buffer( double *buffer, int size,
	double *pmean, double *pstd );
int im__mean_std_int_buffer( int *buffer, int size,
	double *pmean, double *pstd );
int im__find_lroverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
        int bandno_in,
        int xref, int yref, int xsec, int ysec,
        int halfcorrelation, int halfarea,
        int *dx0, int *dy0,
        double *scale1, double *angle1, double *dx1, double *dy1 );
int im__find_tboverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
        int bandno_in,
        int xref, int yref, int xsec, int ysec,
        int halfcorrelation, int halfarea,
        int *dx0, int *dy0,
        double *scale1, double *angle1, double *dx1, double *dy1 );
int im__find_best_contrast( IMAGE *image,
	int xpos, int ypos, int xsize, int ysize,
	int xarray[], int yarray[], int cont[],
	int nbest, int hcorsize );
int im__balance( IMAGE *ref, IMAGE *sec, IMAGE *out,
	IMAGE **ref_out, IMAGE **sec_out, int dx, int dy, int balancetype );
void im__black_region( REGION *reg );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_INTERNAL_H*/
