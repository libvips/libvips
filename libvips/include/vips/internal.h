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

/* What we store in the Meta hash table. We can't just use GHashTable's 
 * key/value pairs, since we need to iterate over meta in Meta_traverse order.
 *
 * We don't refcount at this level ... large meta values are refcounted by
 * their GValue implementation, see eg. MetaArea.
 */
typedef struct _Meta {
	IMAGE *im;

	char *field;			/* strdup() of field name */
	GValue value;			/* copy of value */
} Meta;

void im__meta_init_types( void );
void im__meta_destroy( IMAGE *im );
int im__meta_cp( IMAGE *, const IMAGE * );

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
IMAGE *im_init( const char * );
IMAGE *im_openout( const char * );
IMAGE *im_open_vips( const char * );
int im_openin( IMAGE *image );
int im_openinrw( IMAGE *image );
IMAGE *im_setbuf( const char * );
IMAGE *im_partial( const char * );

int im_mapfile( IMAGE * );
int im_mapfilerw( IMAGE * );
int im_remapfilerw( IMAGE *image );

IMAGE *im_open_header( const char * );

int im_unmapfile( IMAGE * );
void im__read_4byte( int msb_first, unsigned char *to, unsigned char **from );
void im__read_2byte( int msb_first, unsigned char *to, unsigned char **from );
void im__write_4byte( unsigned char **to, unsigned char *from );
void im__write_2byte( unsigned char **to, unsigned char *from );

int im__ftruncate( int fd, gint64 pos );
int im__seek( int fd, gint64 pos );
int im__get_bytes( const char *filename, unsigned char buf[], int len );
gint64 im__image_pixel_length( IMAGE *im );

int im__open_image_file( const char * );
void im__format_init( void );
void im__type_init( void );
int im__read_header_bytes( IMAGE *im, unsigned char *from );
int im__write_header_bytes( IMAGE *im, unsigned char *to );
int im__has_extension_block( IMAGE *im );
void *im__read_extension_block( IMAGE *im, int *size );
int im__write_extension_block( IMAGE *im, void *buf, int size );
int im__writehist( IMAGE *image );
int im__start_eval( IMAGE *im );
int im__handle_eval( IMAGE *im, int w, int h );
int im__end_eval( IMAGE *im );
int im__time_destroy( IMAGE *im );

void im__tiff_register( void );
void im__jpeg_register( void );
void im__png_register( void );
void im__csv_register( void );
void im__ppm_register( void );
void im__analyze_register( void );
void im__exr_register( void );
void im__magick_register( void );

extern int im__read_test;
extern GMutex *im__global_lock;

typedef enum {
	IM__RGB,	/* 1 or 3 bands (like PPM) */
	IM__RGBA,	/* 1, 2, 3 or 4 bands (like PNG) */
	IM__RGB_CMYK	/* 1, 3 or 4 bands (like JPEG) */
} im__saveable_t;

IMAGE *im__convert_saveable( IMAGE *in, 
	im__saveable_t saveable, gboolean sixteen );

void im__link_make( IMAGE *parent, IMAGE *child );
void im__link_break_all( IMAGE *im );
void *im__link_map( IMAGE *im, VSListMap2Fn fn, void *a, void *b );

GValue *im__gvalue_ref_string_new( const char *text );
void im__gslist_gvalue_free( GSList *list );
GSList *im__gslist_gvalue_copy( const GSList *list );
GSList *im__gslist_gvalue_merge( GSList *a, const GSList *b );
char *im__gslist_gvalue_get( const GSList *list );

void im__buffer_init( void );

int im__bandup( IMAGE *in, IMAGE *out, int n );
int im__bandalike( IMAGE *in1, IMAGE *in2, IMAGE *out1, IMAGE *out2 );
int im__formatalike_vec( IMAGE **in, IMAGE **out, int n );
int im__formatalike( IMAGE *in1, IMAGE *in2, IMAGE *out1, IMAGE *out2 );
int im__arith_binary( const char *name, 
	IMAGE *in1, IMAGE *in2, IMAGE *out, 
	int format_table[10], 
	im_wrapmany_fn fn, void *b );
int im__arith_binary_const( const char *name,
	IMAGE *in, IMAGE *out, 
	int n, double *c, VipsBandFmt vfmt,
	int format_table[10], 
	im_wrapone_fn fn1, im_wrapone_fn fnn );
int im__value( IMAGE *im, double *value );
typedef int (*im__wrapscan_fn)( void *p, int n, void *seq, void *a, void *b );
int im__wrapscan( IMAGE *in, 
	im_start_fn start, im__wrapscan_fn scan, im_stop_fn stop,
	void *a, void *b );
int im__colour_difference( const char *domain,
	IMAGE *in1, IMAGE *in2, IMAGE *out, 
	im_wrapmany_fn buffer_fn, void *a, void *b );
int im__colour_unary( const char *domain,
	IMAGE *in, IMAGE *out, VipsType type,
	im_wrapone_fn buffer_fn, void *a, void *b );

/* Structure for holding the lookup tables for XYZ<=>rgb conversion.
 * Also holds the luminance to XYZ matrix and the inverse one.
 */
struct im_col_tab_disp {
	/*< private >*/
	float	t_Yr2r[1501];		/* Conversion of Yr to r */
	float	t_Yg2g[1501];		/* Conversion of Yg to g */
	float	t_Yb2b[1501];		/* Conversion of Yb to b */
	float	t_r2Yr[1501];		/* Conversion of r to Yr */
	float	t_g2Yg[1501];		/* Conversion of g to Yg */
	float	t_b2Yb[1501];		/* Conversion of b to Yb */
	float	mat_XYZ2lum[3][3];	/* XYZ to Yr, Yg, Yb matrix */
	float	mat_lum2XYZ[3][3];	/* Yr, Yg, Yb to XYZ matrix */
	float rstep, gstep, bstep;
	float ristep, gistep, bistep;
};

struct im_col_tab_disp *im_col_make_tables_RGB( IMAGE *im, 
	struct im_col_display *d );
struct im_col_tab_disp *im_col_display_get_table( struct im_col_display *d );

int im__test_kill( IMAGE *im );
void *im__mmap( int fd, int writeable, size_t length, gint64 offset );
int im__munmap( void *start, size_t length );
int im__write( int, const void *, size_t );
void im__change_suffix( const char *name, char *out, int mx,
        const char *new_suff, const char **olds, int nolds );
void im__print_all( void );
void im__print_one( int );
int im__trigger_callbacks( GSList *cblist );
int im__close( IMAGE * );
int im__handle_eval( IMAGE *im, int w, int h );
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

void imb_Lab2LCh( float *, float *, int );
void imb_LCh2Lab( float *, float *, int );
void imb_XYZ2Lab_tables( void );

/* A colour temperature.
 */
typedef struct {
	double X0, Y0, Z0;
} im_colour_temperature;

void imb_XYZ2Lab( float *, float *, int, im_colour_temperature * );
void imb_Lab2XYZ( float *, float *, int, im_colour_temperature * );
void imb_LabQ2Lab( PEL *, float *, int );
void imb_Lab2LabQ( float *, PEL *, int );
void imb_LabS2Lab( signed short *, float *, int );
void imb_Lab2LabS( float *, signed short *, int n );

void im_copy_dmask_matrix( DOUBLEMASK *mask, double **matrix );
void im_copy_matrix_dmask( double **matrix, DOUBLEMASK *mask );

int *im_ivector();
float *im_fvector();
double *im_dvector();
void im_free_ivector();
void im_free_fvector();
void im_free_dvector();

int **im_imat_alloc();
float **im_fmat_alloc();
double **im_dmat_alloc();
void im_free_imat();
void im_free_fmat();
void im_free_dmat();

int im_invmat( double **, int );

int im_conv_f_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
int im_convsep_f_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_INTERNAL_H*/
