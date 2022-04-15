/* helper stuff for Orc
 *
 * 29/10/10
 *	- from im_dilate hackery
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

#ifndef VIPS_VECTOR_H
#define VIPS_VECTOR_H

/* If we are building with -fcf-protection (run-time checking of
 * indirect jumps) then Orc won't work. Make sure it's off.
 *
 * https://gcc.gnu.org/onlinedocs/gcc/\
 * 	Instrumentation-Options.html#index-fcf-protection
 * https://gitlab.freedesktop.org/gstreamer/orc/issues/17
 *
 * orc 0.4.30 and later work with cf-protection.
 */
#ifdef __CET__
#ifndef HAVE_ORC_CF_PROTECTION
#undef HAVE_ORC
#endif
#endif

#ifdef HAVE_ORC
#include <orc/orc.h>
#endif /*HAVE_ORC*/

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_VECTOR_SOURCE_MAX (10)

/* An Orc program. 
 */
typedef struct {
	/* Handy for debugging.
	 */
	const char *name;
	char *unique_name;

	/* How many resources we've used so far in this codegen. 
	 */
	int n_temp;
	int n_scanline;
	int n_source;
	int n_destination;
	int n_constant;
	int n_parameter;
	int n_instruction;

	/* The scanline sources, and for each variable, the associated line.
	 * "sl0" onwards.
	 */
	int sl[VIPS_VECTOR_SOURCE_MAX];
	int line[VIPS_VECTOR_SOURCE_MAX]; 		

	/* Non-scanline sources, "s1" etc. s[0] is the var for "s1".
	 */
	int s[VIPS_VECTOR_SOURCE_MAX];

	/* The destination var.
	 */
	int d1;

#ifdef HAVE_ORC
        /* The code we have generated.
	 */
        OrcProgram *program;
#endif /*HAVE_ORC*/

	/* Compiled successfully.
	 */
	gboolean compiled;
} VipsVector;

/* An executor.
 */
typedef struct {
#ifdef HAVE_ORC
	OrcExecutor executor;
#endif /*HAVE_ORC*/

	VipsVector *vector;
} VipsExecutor;

/* Set from the command-line.
 */
extern gboolean vips__vector_enabled;

VIPS_API
void vips_vector_init( void );
VIPS_API
gboolean vips_vector_isenabled( void );
VIPS_API
void vips_vector_set_enabled( gboolean enabled );

VIPS_API
void vips_vector_free( VipsVector *vector );
VIPS_API
VipsVector *vips_vector_new( const char *name, int dsize );

VIPS_API
void vips_vector_constant( VipsVector *vector, 
	char *name, int value, int size );
VIPS_API
void vips_vector_source_scanline( VipsVector *vector, 
	char *name, int line, int size );
VIPS_API
int vips_vector_source_name( VipsVector *vector, const char *name, int size );
VIPS_API
void vips_vector_temporary( VipsVector *vector, const char *name, int size );
VIPS_API
int vips_vector_parameter( VipsVector *vector, const char *name, int size );
VIPS_API
int vips_vector_destination( VipsVector *vector, const char *name, int size );
VIPS_API
void vips_vector_asm2( VipsVector *vector, 
	const char *op, const char *a, const char *b );
VIPS_API
void vips_vector_asm3( VipsVector *vector, 
	const char *op, const char *a, const char *b, const char *c );
VIPS_API
gboolean vips_vector_full( VipsVector *vector );

VIPS_API
gboolean vips_vector_compile( VipsVector *vector );

VIPS_API
void vips_vector_print( VipsVector *vector );

VIPS_API
void vips_executor_set_program( VipsExecutor *executor, 
	VipsVector *vector, int n );
VIPS_API
void vips_executor_set_scanline( VipsExecutor *executor, 
	VipsRegion *ir, int x, int y );
VIPS_API
void vips_executor_set_destination( VipsExecutor *executor, void *value );
VIPS_API
void vips_executor_set_parameter( VipsExecutor *executor, int var, int value );
VIPS_API
void vips_executor_set_array( VipsExecutor *executor, int var, void *value );

VIPS_API
void vips_executor_run( VipsExecutor *executor ); 

VIPS_API
void vips_vector_to_fixed_point( double *in, int *out, int n, int scale );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_VECTOR_H*/
