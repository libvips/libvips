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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_VECTOR_H
#define IM_VECTOR_H

#ifdef HAVE_ORC
#include <orc/orc.h>
#endif /*HAVE_ORC*/

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* An Orc program. 
 */
typedef struct {
	/* Handy for debugging.
	 */
	const char *name;

	/* How many resources we've used so far in this codegen. 
	 */
	int n_temp;
	int n_source;
	int n_destination;
	int n_constant;
	int n_parameter;
	int n_instruction;

#ifdef HAVE_ORC
        /* The code we have generated.
	 */
        OrcProgram *program;
#endif /*HAVE_ORC*/

	/* Compiled successfully.
	 */
	gboolean compiled;
} VipsVector;

#ifdef HAVE_ORC
typedef OrcExecutor VipsExecutor;
#else /*!HAVE_ORC*/
typedef int VipsExecutor;
#endif /*HAVE_ORC*/

/* Set from the command-line.
 */
extern gboolean im__vector_enabled;

void vips_vector_init( void );
gboolean vips_vector_get_enabled( void );
void vips_vector_set_enabled( gboolean enabled );

void vips_vector_free( VipsVector *vector );
VipsVector *vips_vector_new_ds( const char *name, int size1, int size2 );

void vips_vector_constant( VipsVector *vector, 
	char *name, int value, int size );
void vips_vector_source_name( VipsVector *vector, char *name, int size );
void vips_vector_source( VipsVector *vector, char *name, int number, int size );
void vips_vector_temporary( VipsVector *vector, char *name, int size );
void vips_vector_asm2( VipsVector *vector, 
	const char *op, const char *a, const char *b );
void vips_vector_asm3( VipsVector *vector, 
	const char *op, const char *a, const char *b, const char *c );
gboolean vips_vector_full( VipsVector *vector );

gboolean vips_vector_compile( VipsVector *vector );

void vips_vector_print( VipsVector *vector );

void vips_executor_set_program( VipsExecutor *executor, 
	VipsVector *vector, int n );
void vips_executor_set_source( VipsExecutor *executor, int n, void *value );
void vips_executor_set_destination( VipsExecutor *executor, void *value );
void vips_executor_set_array( VipsExecutor *executor, char *name, void *value );

void vips_executor_run( VipsExecutor *executor );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_VECTOR_H*/
