/* helper functions for Orc
 *
 * 29/10/10
 * 	- from morph hacking
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

/* 

 	TODO

	- would setting params by index rather than name be any quicker?

 */

/* Verbose messages from Orc (or use ORC_DEBUG=99 on the command-line).
#define DEBUG_ORC
 */

/*
#define DEBUG
 */

/* Trace all orc calls, handy for debugging.
#define DEBUG_TRACE
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdlib.h>

#include <vips/vips.h>
#include <vips/vector.h>
#include <vips/internal.h>
#include <vips/thread.h>

/* Cleared by the command-line --vips-novector switch and the IM_NOVECTOR env
 * var.
 */
gboolean vips__vector_enabled = TRUE;

void
vips_vector_error( VipsVector *vector )
{
#ifdef HAVE_ORC_PROGRAM_GET_ERROR
	if( vector->program )
		vips_warn( "VipsVector", "orc error: %s", 
			orc_program_get_error( vector->program ) ); 
#endif /*HAVE_ORC_PROGRAM_GET_ERROR*/
}

void 
vips_vector_init( void )
{
#ifdef HAVE_ORC
#ifdef DEBUG_TRACE
	printf( "orc_init();\n" );
#endif /*DEBUG_TRACE*/
	orc_init();

#ifdef DEBUG_ORC
	/* You can also do ORC_DEBUG=99 at the command-line.
	 */
#ifdef DEBUG_TRACE
	printf( "orc_debug_set_level( 99 );\n" ); 
#endif /*DEBUG_TRACE*/
	orc_debug_set_level( 99 );
#endif /*DEBUG_ORC*/

	/* Look for the environment variable IM_NOVECTOR and use that to turn
	 * off as well.
	 */
	if( g_getenv( "VIPS_NOVECTOR" ) || 
		g_getenv( "IM_NOVECTOR" ) ) 
		vips__vector_enabled = FALSE;
#endif /*HAVE_ORC*/
}

gboolean 
vips_vector_isenabled( void )
{
#ifdef HAVE_ORC
	return( vips__vector_enabled );
#else /*!HAVE_ORC*/
	return( FALSE );
#endif /*HAVE_ORC*/
}

void 
vips_vector_set_enabled( gboolean enabled )
{
	vips__vector_enabled = enabled;
}

void
vips_vector_free( VipsVector *vector )
{
#ifdef HAVE_ORC
	/* orc-0.4.19 will crash if you free programs. Update your orc, or
	 * comment out this line. 
	 *
	 * See https://bugzilla.gnome.org/show_bug.cgi?id=731227
	 *
	 * orc does not set any version variables so we can't disable this
	 * free automatically.
	 */
#ifdef DEBUG_TRACE
	printf( "orc_program_free( %s );\n", vector->unique_name ); 
	printf( "%s = NULL;\n", vector->unique_name ); 
#endif /*DEBUG_TRACE*/
	VIPS_FREEF( orc_program_free, vector->program );
#endif /*HAVE_ORC*/
	VIPS_FREE( vector->unique_name );
	VIPS_FREE( vector );
}

VipsVector *
vips_vector_new( const char *name, int dsize )
{
	static int vector_number = 0;

	VipsVector *vector;
	int i;

	if( !(vector = VIPS_NEW( NULL, VipsVector )) )
		return( NULL );
	vector->name = name;
	vector->unique_name = g_strdup_printf( "p[%d]", vector_number++ );
	vector->n_temp = 0;
	vector->n_scanline = 0;
	vector->n_source = 0;
	vector->n_destination = 0;
	vector->n_constant = 0;
	vector->n_parameter = 0;
	vector->n_instruction = 0;

	for( i = 0; i < VIPS_VECTOR_SOURCE_MAX; i++ ) {
		vector->s[i] = -1;
		vector->sl[i] = -1;
	}

	vector->d1 = -1;

	vector->compiled = FALSE;

#ifdef HAVE_ORC
	vector->program = orc_program_new();
#ifdef DEBUG_TRACE
	printf( "%s = orc_program_new();\n", vector->unique_name );
#endif /*DEBUG_TRACE*/
#endif /*HAVE_ORC*/

	/* We always make d1, our callers make either a single point source, or
	 * for area ops, a set of scanlines.
	 *
	 * Don't check error return. orc uses 0 to mean error, but the first
	 * var you create will have id 0 :-( The first var is unlikely to fail
	 * anyway. 
	 */
	vector->d1 = vips_vector_destination( vector, "d1", dsize ); 

	return( vector );
}

void 
vips_vector_asm2( VipsVector *vector, 
	const char *op, const char *a, const char *b )
{
	vector->n_instruction += 1;

#ifdef DEBUG
	 printf( "  %s %s %s\n", op, a, b );
#endif /*DEBUG*/

#ifdef HAVE_ORC
#ifdef DEBUG_TRACE
	printf( "orc_program_append_ds_str( %s, \"%s\", \"%s\", \"%s\" );\n",
		vector->unique_name, op, a, b ); 
#endif /*DEBUG_TRACE*/
	 orc_program_append_ds_str( vector->program, op, a, b );
#endif /*HAVE_ORC*/
}

void 
vips_vector_asm3( VipsVector *vector, 
	const char *op, const char *a, const char *b, const char *c )
{
	vector->n_instruction += 1;

#ifdef DEBUG
	 printf( "  %s %s %s %s\n", op, a, b, c );
#endif /*DEBUG*/

#ifdef HAVE_ORC
#ifdef DEBUG_TRACE
	printf( "orc_program_append_str( %s, \"%s\", "
		"\"%s\", \"%s\", \"%s\" );\n",
		vector->unique_name, op, a, b, c ); 
#endif /*DEBUG_TRACE*/
	 orc_program_append_str( vector->program, op, a, b, c );
#endif /*HAVE_ORC*/
}

void
vips_vector_constant( VipsVector *vector, char *name, int value, int size )
{
#ifdef HAVE_ORC
	char *sname;

	if( size == 1 )
		sname = "b";
	else if( size == 2 )
		sname = "w";
	else if( size == 4 )
		sname = "l";
	else {
		printf( "vips_vector_constant: bad constant size\n" );

		/* Not really correct, heh.
		 */
		sname = "x";
	}

	if( value > 0 )
		vips_snprintf( name, 256, "c%d%s", value, sname );
	else
		vips_snprintf( name, 256, "cm%d%s", -value, sname );

	if( orc_program_find_var_by_name( vector->program, name ) == -1 ) {
#ifdef DEBUG_TRACE
		printf( "orc_program_add_constant( %s, %d, %d, \"%s\" );\n", 
			vector->unique_name, size, value, name ); 
#endif /*DEBUG_TRACE*/
		if( !orc_program_add_constant( vector->program, 
			size, value, name ) )
			vips_vector_error( vector );
		vector->n_constant += 1;
	}
#endif /*HAVE_ORC*/
}

void
vips_vector_source_scanline( VipsVector *vector, 
	char *name, int line, int size )
{
#ifdef HAVE_ORC
	vips_snprintf( name, 256, "sl%d", line );

	if( orc_program_find_var_by_name( vector->program, name ) == -1 ) {
		int var;

		if( !(var = orc_program_add_source( vector->program, 
			size, name )) ) 
			vips_vector_error( vector );
#ifdef DEBUG_TRACE
		printf( "orc_program_add_source( %s, %d, \"%s\" );\n",
			vector->unique_name, size, name );
#endif /*DEBUG_TRACE*/
		vector->sl[vector->n_scanline] = var;
		vector->line[vector->n_scanline] = line;
		vector->n_scanline += 1;
	}
#endif /*HAVE_ORC*/
}

int
vips_vector_source_name( VipsVector *vector, const char *name, int size )
{
	int var;

#ifdef HAVE_ORC
	g_assert( orc_program_find_var_by_name( vector->program, name ) == -1 );

	if( !(var = orc_program_add_source( vector->program, size, name )) )
		vips_vector_error( vector ); 
	vector->s[vector->n_source] = var;
#ifdef DEBUG_TRACE
	printf( "orc_program_add_source( %s, %d, \"%s\" );\n", 
		vector->unique_name, size, name );
#endif /*DEBUG_TRACE*/
	vector->n_source += 1;
#else /*!HAVE_ORC*/
	var = -1;
#endif /*HAVE_ORC*/

	return( var );
}

void
vips_vector_temporary( VipsVector *vector, const char *name, int size )
{
#ifdef HAVE_ORC
	g_assert( orc_program_find_var_by_name( vector->program, name ) == -1 );

	if( !orc_program_add_temporary( vector->program, size, name ) )
		vips_vector_error( vector ); 

#ifdef DEBUG_TRACE
	printf( "orc_program_add_temporary( %s, %d, \"%s\" );\n",
		vector->unique_name, size, name );
#endif /*DEBUG_TRACE*/
	vector->n_temp += 1;
#endif /*HAVE_ORC*/
}

int
vips_vector_parameter( VipsVector *vector, const char *name, int size )
{
	int var;

#ifdef HAVE_ORC
	g_assert( orc_program_find_var_by_name( vector->program, name ) == -1 );

	var = orc_program_add_parameter( vector->program, size, name );
	if( !var )
		vips_vector_error( vector ); 

#ifdef DEBUG_TRACE
	printf( "orc_program_add_parameter( %s, %d, \"%s\" );\n",
		vector->unique_name, size, name );
#endif /*DEBUG_TRACE*/
	vector->n_parameter += 1;
#else /*!HAVE_ORC*/
	var = -1;
#endif /*HAVE_ORC*/

	return ( var ); 
}

int
vips_vector_destination( VipsVector *vector, const char *name, int size )
{
	int var;

#ifdef HAVE_ORC
	g_assert( orc_program_find_var_by_name( vector->program, name ) == -1 );

	var = orc_program_add_destination( vector->program, size, name );
#ifdef DEBUG_TRACE
	printf( "orc_program_add_destination( %d, \"%s\" );\n",
		size, name );
#endif /*DEBUG_TRACE*/
	vector->n_destination += 1;
#else /*!HAVE_ORC*/
	var = -1;
#endif /*HAVE_ORC*/

	return( var ); 
}

gboolean
vips_vector_full( VipsVector *vector )
{
	/* Many orcs don't have ORC_MAX_CONST_VARS etc., stick to our own
	 * constants for now.
	 */

	/* We can need a max of 2 constants plus one source per
	 * coefficient, so stop if we're sure we don't have enough.
	 */
	if( vector->n_constant + 2 > 8 )
		return( TRUE );

	/* You can have 8 source, and d1 counts as one of them, so +1
	 * there.
	 */
	if( vector->n_source + vector->n_scanline + 1 > 7 )
		return( TRUE );

	/* Need to leave some space, so 1 spare. 
	 */
	if( vector->n_parameter > 7 )
		return( TRUE );

	/* After signalling full, some operations will add up to 4 more 
	 * instructions as they finish up. Leave a margin.
	 */
	if( vector->n_instruction + 10 > 50 )
		return( TRUE );

	return( FALSE );
}

gboolean
vips_vector_compile( VipsVector *vector )
{
#ifdef HAVE_ORC
	OrcCompileResult result;

	/* Some orcs seem to be unstable with many compilers active at once.
	 */
	g_mutex_lock( vips__global_lock );
	result = orc_program_compile( vector->program );
	g_mutex_unlock( vips__global_lock );

#ifdef DEBUG_TRACE
	printf( "orc_program_compile( %s );\n", vector->unique_name );
#endif /*DEBUG_TRACE*/
	if( !ORC_COMPILE_RESULT_IS_SUCCESSFUL( result ) ) {
#ifdef DEBUG
		printf( "*** error compiling %s\n", vector->name );
#endif /*DEBUG*/

		return( FALSE );
	}

	vector->compiled = TRUE;
#endif /*HAVE_ORC*/

	return( TRUE );
}

void
vips_vector_print( VipsVector *vector )
{
	int i;

	printf( "%s: ", vector->name );
	if( vector->compiled )
		printf( "successfully compiled\n" );
	else
		printf( "not compiled\n" );
	printf( "  n_scanline = %d\n", vector->n_scanline );
	for( i = 0; i < vector->n_scanline; i++ )
		printf( "        var %d = line %d\n", 
			vector->sl[i], vector->line[i] ); 
	printf( "  n_source = %d\n", vector->n_source );
	for( i = 0; i < vector->n_source; i++ )
		printf( "        var %d\n", vector->s[i] );
	printf( "  n_parameter = %d\n", vector->n_parameter );
	printf( "  n_destination = %d\n", vector->n_destination );
	printf( "  n_constant = %d\n", vector->n_constant );
	printf( "  n_temp = %d\n", vector->n_temp );
	printf( "  n_instruction = %d\n", vector->n_instruction );
}

void
vips_executor_set_program( VipsExecutor *executor, VipsVector *vector, int n )
{
#ifdef HAVE_ORC
	executor->vector = vector;

	orc_executor_set_program( &executor->executor, vector->program );
	orc_executor_set_n( &executor->executor, n );
#endif /*HAVE_ORC*/
}

void
vips_executor_set_array( VipsExecutor *executor, int var, void *value )
{
#ifdef HAVE_ORC
	if( var != -1 )  
		orc_executor_set_array( &executor->executor, var, value );
#endif /*HAVE_ORC*/
}

void
vips_executor_set_parameter( VipsExecutor *executor, int var, int value )
{
#ifdef HAVE_ORC
	if( var != -1 )  
		orc_executor_set_param( &executor->executor, var, value );
#endif /*HAVE_ORC*/
}

void
vips_executor_set_scanline( VipsExecutor *executor, 
	VipsRegion *ir, int x, int y )
{
	VipsVector *vector = executor->vector;
	VipsPel *base = VIPS_REGION_ADDR( ir, x, y );
	int lsk = VIPS_REGION_LSKIP( ir );

	int i;

	for( i = 0; i < vector->n_scanline; i++ ) 
		vips_executor_set_array( executor, 
			vector->sl[i], base + vector->line[i] * lsk );
}

void
vips_executor_set_destination( VipsExecutor *executor, void *value )
{
	VipsVector *vector = executor->vector;

	vips_executor_set_array( executor, vector->d1, value );
}

void
vips_executor_run( VipsExecutor *executor )
{
#ifdef HAVE_ORC
	orc_executor_run( &executor->executor );
#endif /*HAVE_ORC*/
}

/* Make a fixed-point version of a matrix. Each 
 * out[i] = rint(in[i] * adj_scale), where adj_scale is selected so that 
 * sum(out) = sum(in) * scale.
 *
 * Because of the vagaries of rint(), we can't just calc this, we have to
 * iterate and converge on the best value for adj_scale.
 */
void
vips_vector_to_fixed_point( double *in, int *out, int n, int scale )
{
	double fsum;
	int i;
	int target;
	int sum;
	double high;
	double low;
	double guess;

	fsum = 0.0;
	for( i = 0; i < n; i++ )
		fsum += in[i];
	target = VIPS_RINT( fsum * scale );

	/* As we rint() each scale element, we can get up to 0.5 error.
	 * Therefore, by the end of the mask, we can be off by up to n/2. Our
	 * high and low guesses are therefore n/2 either side of the obvious
	 * answer.
	 */
	high = scale + (n + 1) / 2;
	low = scale - (n + 1) / 2;

	do {
		guess = (high + low) / 2.0;

		for( i = 0; i < n; i++ ) 
			out[i] = VIPS_RINT( in[i] * guess );

		sum = 0;
		for( i = 0; i < n; i++ )
			sum += out[i];

		if( sum == target )
			break;
		if( sum < target )
			low = guess;
		if( sum > target )
			high = guess;

	/* This will typically produce about 5 iterations.
	 */
	} while( high - low > 0.01 );

	if( sum != target ) {
		/* Spread the error out thinly over the whole array. For
		 * example, consider the matrix:
		 *
		 * 	3 3 9 0
		 *	1 1 1
		 *	1 1 1
		 *	1 1 1
		 *
		 * being converted with scale = 64 (convi does this). We want
		 * to generate a mix of 7s and 8s. 
		 */
		int each_error = (target - sum) / n;
		int extra_error = (target - sum) % n;

		/* To share the residual error, we add or subtract 1 from the
		 * first abs(extra_error) elements.
		 */
		int direction = extra_error > 0 ? 1 : -1;
		int n_elements = VIPS_ABS( extra_error );

		for( i = 0; i < n; i++ )
			out[i] += each_error;

		for( i = 0; i < n_elements; i++ )
			out[i] += direction;
	}
}
