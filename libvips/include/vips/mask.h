/* mask.h
 *
 * 20/9/09
 * 	- from proto.h
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

#ifndef IM_MASK_H
#define IM_MASK_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int poop( int poop );

typedef struct im__INTMASK {
	int xsize;
	int ysize;
	int scale;
	int offset;
	int *coeff;
	char *filename;
} INTMASK;

typedef struct im__DOUBLEMASK {
	int xsize;
	int ysize;
	double scale;
	double offset;
	double *coeff;
	char *filename;
} DOUBLEMASK;

void im_copy_dmask_matrix( DOUBLEMASK *mask, double **matrix );
void im_copy_matrix_dmask( double **matrix, DOUBLEMASK *mask );

INTMASK *im_create_imask( const char *name, int width, int height );
INTMASK *im_create_imaskv( const char *name, int width, int height, ... );
DOUBLEMASK *im_create_dmask( const char *name, int width, int height );
DOUBLEMASK *im_create_dmaskv( const char *name, int width, int height, ... );

INTMASK *im_log_imask( const char *name, double, double );
DOUBLEMASK *im_log_dmask( const char *name, double, double );
INTMASK *im_gauss_imask( const char *name, double, double );
INTMASK *im_gauss_imask_sep( const char *name, double, double );
DOUBLEMASK *im_gauss_dmask( const char *name, double, double );

INTMASK *im_dup_imask( INTMASK *m, const char *name );
DOUBLEMASK *im_dup_dmask( DOUBLEMASK *m, const char *name );

int im_free_imask( INTMASK *m );
int im_free_dmask( DOUBLEMASK *m );

INTMASK *im_read_imask( const char *filename );
DOUBLEMASK *im_read_dmask( const char *filename );

void im_print_imask( INTMASK *m );
void im_print_dmask( DOUBLEMASK *m );

int im_write_imask( INTMASK *m );
int im_write_dmask( DOUBLEMASK *m );
int im_write_imask_name( INTMASK *m, const char *filename );
int im_write_dmask_name( DOUBLEMASK *m, const char *filename );

INTMASK *im_scale_dmask( DOUBLEMASK *m, const char *name );
void im_norm_dmask( DOUBLEMASK *mask );
int *im_offsets45( int );
int *im_offsets90( int );
INTMASK *im_rotate_imask90( INTMASK *m, const char *name );
INTMASK *im_rotate_imask45( INTMASK *m, const char *name );
DOUBLEMASK *im_rotate_dmask90( DOUBLEMASK *m, const char *name );
DOUBLEMASK *im_rotate_dmask45( DOUBLEMASK *m, const char *name );

DOUBLEMASK *im_mattrn( DOUBLEMASK *, const char * );
DOUBLEMASK *im_matcat( DOUBLEMASK *, DOUBLEMASK *, const char * );
DOUBLEMASK *im_matmul( DOUBLEMASK *, DOUBLEMASK *, const char * );

DOUBLEMASK *im_lu_decomp( const DOUBLEMASK *mat, const char *name );
int im_lu_solve( const DOUBLEMASK *lu, double *vec );
DOUBLEMASK *im_matinv( const DOUBLEMASK *mat, const char *name );
int im_matinv_inplace( DOUBLEMASK *mat );

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

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_MASK_H*/
