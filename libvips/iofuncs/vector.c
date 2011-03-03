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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdlib.h>

#include <vips/vips.h>
#include <vips/vector.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Cleared by the command-line --vips-novector switch and the IM_NOVECTOR env
 * var.
 */
gboolean im__vector_enabled = TRUE;

void 
vips_vector_init( void )
{
#ifdef HAVE_ORC
	orc_init();

#ifdef DEBUG_ORC
	/* You can also do ORC_DEBUG=99 at the command-line.
	 */
	orc_debug_set_level( 99 );
#endif /*DEBUG_ORC*/

	/* Look for the environment variable IM_NOVECTOR and use that to turn
	 * off as well.
	 */
	if( g_getenv( "IM_NOVECTOR" ) ) 
		im__vector_enabled = FALSE;
#endif /*HAVE_ORC*/
}

gboolean 
vips_vector_get_enabled( void )
{
#ifdef HAVE_ORC
	return( im__vector_enabled );
#else /*!HAVE_ORC*/
	return( FALSE );
#endif /*HAVE_ORC*/
}

void 
vips_vector_set_enabled( gboolean enabled )
{
	im__vector_enabled = enabled;
}

void
vips_vector_free( VipsVector *vector )
{
#ifdef HAVE_ORC
	VIPS_FREEF( orc_program_free, vector->program );
#endif /*HAVE_ORC*/
	VIPS_FREE( vector );
}

VipsVector *
vips_vector_new( const char *name, int dsize )
{
	VipsVector *vector;
	int i;

	if( !(vector = VIPS_NEW( NULL, VipsVector )) )
		return( NULL );
	vector->name = name;
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

	/* We always make d1, our callers make either a single point source, or
	 * for area ops, a set of scanlines.
	 */
	vector->d1 = orc_program_add_destination( vector->program, 
		dsize, "d1" );
	vector->n_destination += 1;
#endif /*HAVE_ORC*/

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
		im_snprintf( name, 256, "c%d%s", value, sname );
	else
		im_snprintf( name, 256, "cm%d%s", -value, sname );

	if( orc_program_find_var_by_name( vector->program, name ) == -1 ) {
		orc_program_add_constant( vector->program, size, value, name );
		vector->n_constant += 1;
	}
#endif /*HAVE_ORC*/
}

int
vips_vector_source_name( VipsVector *vector, char *name, int size )
{
	int var;

#ifdef HAVE_ORC
	g_assert( orc_program_find_var_by_name( vector->program, name ) == -1 );

	vector->s[vector->n_source] = var =
		orc_program_add_source( vector->program, size, name );
	vector->n_source += 1;
#else /*!HAVE_ORC*/
	var = -1;
#endif /*HAVE_ORC*/

	return( var );
}

void
vips_vector_source_scanline( VipsVector *vector, 
	char *name, int line, int size )
{
#ifdef HAVE_ORC
	im_snprintf( name, 256, "sl%d", line );

	if( orc_program_find_var_by_name( vector->program, name ) == -1 ) {
		int var;

		var = orc_program_add_source( vector->program, size, name );
		vector->sl[vector->n_scanline] = var;
		vector->line[vector->n_scanline] = line;
		vector->n_scanline += 1;
	}
#endif /*HAVE_ORC*/
}

void
vips_vector_temporary( VipsVector *vector, char *name, int size )
{
#ifdef HAVE_ORC
	g_assert( orc_program_find_var_by_name( vector->program, name ) == -1 );

	orc_program_add_temporary( vector->program, size, name );
	vector->n_temp += 1;
#endif /*HAVE_ORC*/
}

gboolean
vips_vector_full( VipsVector *vector )
{
	/* We can need a max of 2 constants plus one source per
	 * coefficient, so stop if we're sure we don't have enough.
	 */
	if( vector->n_constant > 16 - 2 )
		return( TRUE );

	/* You can have 8 parameters, and d1 counts as one of them, so +1
	 * there.
	 */
	if( vector->n_source + vector->n_scanline + 1 > 7 )
		return( TRUE );

	/* I seem to get segvs with I counts over about 50 :-( argh.
	 */
	if( vector->n_instruction > 45 )
		return( TRUE );

	return( FALSE );
}

gboolean
vips_vector_compile( VipsVector *vector )
{
#ifdef HAVE_ORC
	OrcCompileResult result;

	result = orc_program_compile( vector->program );
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
		printf( "not compiled successfully\n" );
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
vips_executor_set_scanline( VipsExecutor *executor, 
	VipsRegion *ir, int x, int y )
{
	VipsVector *vector = executor->vector;
	PEL *base = (PEL *) VIPS_REGION_ADDR( ir, x, y );
	int lsk = VIPS_REGION_LSKIP( ir );

	int i;

	for( i = 0; i < vector->n_scanline; i++ ) {
		vips_executor_set_array( executor, 
			vector->sl[i], base + vector->line[i] * lsk );
	}
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
