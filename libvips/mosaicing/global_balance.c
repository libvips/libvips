/* Parse ".desc" files from mosaiced images to generate (x,y) offsets for
 * every sub-image. Find all overlap stats and solve balancing with LMS.
 * Regenerate mosaic, with balancing fixed.
 * 
 * 1/12/93 JC
 *	- first version, unfinished!
 * 6/9/95 JC
 *	- LMS fixed, now works, more or less
 * 12/9/95 JC
 *	- now does positions correctly too
 *	- ignores trivial overlaps
 * 19/9/95 JC
 *	- prints correct number of balance factors!
 * 10/11/95 JC
 *	- now tracks im_copy() calls too, so you can save sub-images
 * 12/1/96 JC
 *	- slightly clearer diagnostics
 *	- better centre of factors around 1.0 with log() average
 * 1/3/96 JC
 *	- new im_global_balance_float variant lets our caller adjust factor
 *	  range if output has burn-out
 *	- im_global_balance_search uses the above to produce scaled output ...
 *	  very slow!
 * 11/3/96 JC
 *	- now tries current directory too for input files
 * 22/3/96 JC
 *	- horrible bug in position finding! now fixed
 * 1/8/97 JC
 *	- revised for new mosaic functions and non-square images
 * 12/9/97 JC
 *	- code for im_lrmosaic1() support
 *	- output type == input type, so works for short images too
 * 6/1/99 JC
 *	- new gamma parameter, do scale in linear space
 *	- removed _search version, as can now be done with ip
 *	- renamed _float to f suffix, in line with im_conv()/im_convf()
 * 15/2/00 JC
 *	- balancef() did not scale in linear space
 * 2/2/01 JC
 *	- added tunable max blend width
 * 7/11/01 JC
 *	- global_balance.h broken out for im_remosaic()
 * 25/02/02 JC
 *	- better transform function scheme
 * 21/3/01 JC
 *	- quicker bailout on error
 * 8/11/02 JC
 * 	- add <> around file names so you can have spaces :(
 * 9/12/02 JC
 *	- track original params and always reuse them ... makes us proof
 *	  against geo reconstruct errors
 * 10/3/03 JC
 *	- weed out overlaps which contain only transparent pixels
 * 4/1/07
 * 	- switch to new history thing, switch im_errormsg() too
 * 24/1/11
 * 	- gtk-doc
 * 12/7/12
 * 	- always allocate local to an output descriptor ... stops ref cycles
 * 	  with the new base class
 * 18/6/20 kleisauke
 * 	- convert to vips8
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

/* Strategy: build a tree describing the file
 * relationships in the desc file, then walk that passing constraints
 * back up to the root. Look up file names in symbol_table.
 */

/* Define for debug output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/transform.h>
#include <vips/internal.h>

#include "pmosaicing.h"
#include "global_balance.h"

#define MAX_ITEMS (50)

/* How pix an overlap has to be (in pixels) before we think it's trivial and
 * we ignore it.
 */
#define TRIVIAL (20 * 20)

/* Break a string into a list of strings. Write '\0's into the string. out
 * needs to be MAX_FILES long. -1 for error, otherwise number of args found.

	"<fred> <jim poop> <sn aff le>"

	out[0] = "fred"
	out[1] = "jim poop"
	out[2] = "sn aff le"

 */
static int
break_items( char *line, char **out )
{
	int i;
	char *p;

	for( i = 0; i < MAX_ITEMS; i++ ) {
		/* Skip to first '<'.
		 */
		if( !(p = strchr( line, '<' )) )
			break;

		out[i] = line = p + 1;

		if( !(p = strchr( line, '>' )) ) {
			vips_error( "break_files", "%s", _( "no matching '>'" ) );
			return( -1 );
		}

		*p = '\0';
		line = p + 1;
	}

	if( i == MAX_ITEMS ) {
		vips_error( "break_files", "%s", _( "too many items" ) );
		return( -1 );
	}

	return( i );
}

/* Try to open a file. If full path fails, try the current directory.
 */
VipsImage *
vips__global_open_image( SymbolTable *st, char *name )
{
	char *basename;
	VipsImage *image;

	if( !(image = vips_image_new_from_file( name, NULL ))) {
		/* TODO(kleisauke): Is this behavior the same as im_skip_dir?
		 * i.e. could we open a filename which came
		 * from a win32 (`\\`) on a *nix machine? 
		 */
		basename = g_path_get_basename( name );

		if( !(image = vips_image_new_from_file( basename, NULL ))) {
			g_free( basename );
			return( NULL );
		}

		g_free( basename );
	}

	vips_object_local( st->im, image );

	return( image );
}

static void
junk_node( VipsImage *image, JoinNode *node )
{
	VIPS_FREEF( g_slist_free, node->overlaps );
}

/* Hash from a filename to an index into symbol_table.
 */
static int
hash( char *n )
{
	int i;
	int r = 0;
	int l = strlen( n );

	for( i = 0; i < l; i++ )
		r = ((r + n[i]) * 43) & 0xffffff;

	return( r % SYM_TAB_SIZE );
}

/* Make a leaf for a file.
 */
static JoinNode *
build_node( SymbolTable *st, char *name )
{
	JoinNode *node = VIPS_NEW( st->im, JoinNode );
	int n = hash( name );

	/* Fill fields.
	 */
	if( !node || !(node->name = 
		vips_strdup( VIPS_OBJECT( st->im ), name )) )
		return( NULL );

	node->type = JOIN_LEAF;
	node->dirty = 0;
	node->mwidth = -2;
	node->st = st;
	vips__transform_init( &node->cumtrn );
	node->trnim = NULL;
	node->arg1 = NULL;
	node->arg2 = NULL;
	node->overlaps = NULL;
	node->im = NULL;
	node->index = 0;

	g_signal_connect( st->im, "close",
		G_CALLBACK( junk_node ), node );

	/* Try to open.
	 */
	if( (node->im = vips__global_open_image( st, name )) ) {
		/* There is a file there - set width and height.
		 */
		node->cumtrn.oarea.width = node->im->Xsize;
		node->cumtrn.oarea.height = node->im->Ysize;
	}
	else {
		/* Clear the error buffer to lessen confusion.
		 */
		vips_error_clear();
	}

	st->table[n] = g_slist_prepend( st->table[n], node );

	return( node );
}

/* Make a new overlap struct.
 */
static OverlapInfo *
build_overlap( JoinNode *node, JoinNode *other, VipsRect *overlap )
{
	OverlapInfo *lap = VIPS_NEW( node->st->im, OverlapInfo );

	if( !lap )
		return( NULL );

	lap->node = node;
	lap->other = other;
	lap->overlap = *overlap;
	lap->nstats = NULL;
	lap->ostats = NULL;
	node->overlaps = g_slist_prepend( node->overlaps, lap );
	node->st->novl++;

	return( lap );
}

static void
overlap_destroy( OverlapInfo *lap )
{
	JoinNode *node = lap->node;

	node->overlaps = g_slist_remove( node->overlaps, lap );
	g_assert( node->st->novl > 0 );
	node->st->novl--;
}

static void
junk_table( VipsImage *image, SymbolTable *st ) {
	int i;

	for( i = 0; i < st->sz; i++ )
		VIPS_FREEF( g_slist_free, st->table[i] );
}

/* Build a new symbol table.
 */
SymbolTable *
vips__build_symtab( VipsImage *out, int sz )
{
	SymbolTable *st = VIPS_NEW( out, SymbolTable );
	int i;

	if( !st ||
		!(st->table = VIPS_ARRAY( out, sz, GSList * )) )
		return( NULL );
	st->sz = sz;
	st->im = out;
	st->novl = 0;
	st->nim = 0;
	st->njoin = 0;
	st->root = NULL;
	st->leaf = NULL;
	st->fac = NULL;

	g_signal_connect( out, "close", 
		G_CALLBACK( junk_table ), st );

	for( i = 0; i < sz; i++ )
		st->table[i] = NULL;

	return( st );
}

/* Does this node have this file name?
 */
static JoinNode *
test_name( JoinNode *node, char *name, void *b )
{
	if( strcmp( node->name, name ) == 0 )
		return( node );
	else
		return( NULL );
}

/* Look up a filename in the symbol_table.
 */
static JoinNode *
find_node( SymbolTable *st, char *name ) 
{
	return( vips_slist_map2( st->table[hash( name )],
		(VipsSListMap2Fn) test_name, name, NULL ) );
}

/* Given a name: return either the existing node for that name, or a new node
 * we have made.
 */
static JoinNode *
add_node( SymbolTable *st, char *name )
{
	JoinNode *node;

	if( !(node = find_node( st, name )) && 
		!(node = build_node( st, name )) )
		return( NULL );

	return( node );
}

/* Map a user function over the whole of the symbol table. 
 */
void *
vips__map_table( SymbolTable *st, VipsSListMap2Fn fn, void *a, void *b )
{
	int i;
	void *r;
	
	for( i = 0; i < st->sz; i++ )
		if( (r = vips_slist_map2( st->table[i], fn, a, b )) )
			return( r );
	
	return( NULL );
}

/* Set the dirty field on a join.
 */
static void *
set_dirty( JoinNode *node, int state, void *b )
{	
	node->dirty = state;

	return( NULL );
}

/* Clean the whole table.
 */
static void
clean_table( SymbolTable *st )
{
	(void) vips__map_table( st, 
		(VipsSListMap2Fn) set_dirty, (void *) 0, NULL );
}

/* Do geometry calculations on a node, assuming geo is up to date for any 
 * children.
 */
static void
calc_geometry( JoinNode *node )
{
	VipsRect um;

	switch( node->type ) {
	case JOIN_LR:
	case JOIN_TB:
	case JOIN_LRROTSCALE:
	case JOIN_TBROTSCALE:
		/* Join two areas.
		 */
		vips_rect_unionrect( &node->arg1->cumtrn.oarea,
			&node->arg2->cumtrn.oarea, &um );
		node->cumtrn.iarea.left = 0;
		node->cumtrn.iarea.top = 0;
		node->cumtrn.iarea.width = um.width;
		node->cumtrn.iarea.height = um.height;
		vips__transform_set_area( &node->cumtrn );
		break;

	case JOIN_CP:
		/* Copy from child.
		 */
		node->cumtrn = node->arg1->cumtrn;
		break;

	case JOIN_LEAF:
		/* Just use leaf dimensions, if there are any.
		 */
		if( node->im ) {
			node->cumtrn.iarea.left = 0;
			node->cumtrn.iarea.top = 0;
			node->cumtrn.iarea.width = node->im->Xsize;
			node->cumtrn.iarea.height = node->im->Ysize;
			vips__transform_set_area( &node->cumtrn );
		}
		break;

	default:
		vips_error_exit( "internal error #98356" );
		/*NOTREACHED*/
	}
}

/* Propagate a transform down a tree. If dirty is set, we've been here before,
 * so there is a doubling up of this node. If this is a leaf, then we have the
 * same leaf twice (which, in fact, we can cope with); if this is a node, we 
 * have circularity.
 */
static int
propagate_transform( JoinNode *node, VipsTransformation *trn )
{
	if( !node )
		return( 0 );

	if( node->dirty && node->arg1 && node->arg2 ) {
		vips_error( "vips_global_balance", 
			"%s", _( "circularity detected" ) );
		return( -1 );
	}
	node->dirty = 1;

	/* Transform our children.
	 */
	if( propagate_transform( node->arg1, trn ) ||
		propagate_transform( node->arg2, trn ) )
		return( -1 );

	/* Transform us, and recalculate our position and size.
	 */
	vips__transform_add( &node->cumtrn, trn, &node->cumtrn );
	calc_geometry( node );

	return( 0 );
}

/* Ah ha! A leaf is actually made up of two smaller files with an lr or a tb
 * merge. Turn a leaf node into a join node. Propagate the transform down 
 * arg2's side of the tree.
 */
static int
make_join( SymbolTable *st, JoinType type, 
	JoinNode *arg1, JoinNode *arg2, JoinNode *out, 
	double a, double b, double dx, double dy, int mwidth )
{
	VipsTransformation trn;

	/* Check output is ok.
	 */
	if( out->type != JOIN_LEAF ) {
		vips_error( "vips_global_balance", 
			_( "image \"%s\" used twice as output" ), out->name );
		return( -1 );
	}

	/* Fill fields.
	 */
	out->type = type;
	out->mwidth = mwidth;
	out->a = a;
	out->b = b;
	out->dx = dx;
	out->dy = dy;
	out->arg1 = arg1;
	out->arg2 = arg2;
	out->thistrn.a = a;
	out->thistrn.b = -b;
	out->thistrn.c = b;
	out->thistrn.d = a;
	out->thistrn.idx = 0;
	out->thistrn.idy = 0;
	out->thistrn.odx = dx;
	out->thistrn.ody = dy;

	/* Clean the table and propagate the transform down the RHS of the
	 * graph.
	 */
	clean_table( st );
	if( propagate_transform( arg2, &out->thistrn ) )
		return( -1 );

	/* Find the position and size of our output.
	 */
	calc_geometry( out );

	/* Now normalise the result, so that out is at (0,0) again.
	 */
	trn.a = 1.0;
	trn.b = 0.0;
	trn.c = 0.0;
	trn.d = 1.0;
	trn.idx = 0;
	trn.idy = 0;
	trn.odx = -out->cumtrn.oarea.left;
	trn.ody = -out->cumtrn.oarea.top;
	clean_table( st );
	if( propagate_transform( out, &trn ) )
		return( -1 );

	return( 0 );
}

/* Make a copy node.
 */
static int
make_copy( SymbolTable *st, JoinNode *before, JoinNode *after )
{
	/* Check output is ok.
	 */
	if( after->type != JOIN_LEAF ) {
		vips_error( "vips_global_balance", 
			_( "image \"%s\" used twice as output" ), after->name );
		return( -1 );
	}

	/* Fill fields.
	 */
	after->type = JOIN_CP;
	after->arg1 = before;
	after->arg2 = NULL;

	/* Copy over the position and size from the before to the after.
	 */
	calc_geometry( after ); 

	return( 0 );
}

/* Process a single .desc line.
 */
static int
process_line( SymbolTable *st, const char *text )
{
	char line[1024];

#ifdef DEBUG
	printf( "read: %s\n", text );
#endif /*DEBUG*/

	/* We destroy line during the parse.
	 */
	vips_strncpy( line, text, 1024 );

	if( vips_isprefix( "#LRJOIN ", line ) ||
		vips_isprefix( "#TBJOIN ", line ) ) {
		/* Yes: magic join command. Break into tokens. Format is eg.

			#LRJOIN <left> <right> <out> <x> <y> [<mwidth>]

		 */
		char *item[MAX_ITEMS];
		int nitems;
		JoinType type;
		JoinNode *arg1, *arg2, *join;
		int dx, dy, mwidth;

		if( (nitems = break_items( line, item )) < 0 )
			return( -1 );
		if( nitems != 5 && nitems != 6 ) {
			vips_error( "global_balance", 
				"%s", _( "bad number of args in join line" ) );
			return( -1 );
		}

		if( !(arg1 = add_node( st, item[0] )) ||
			!(arg2 = add_node( st, item[1] )) ||
			!(join = add_node( st, item[2] )) )
			return( -1 );
		dx = atoi( item[3] );
		dy = atoi( item[4] );
		if( nitems == 6 ) 
			mwidth = atoi( item[5] );
		else
			mwidth = -1;
		if( vips_isprefix( "#LRJOIN ", line ) )
			type = JOIN_LR;
		else
			type = JOIN_TB;

		if( make_join( st, type, arg1, arg2, 
			join, 1.0, 0.0, dx, dy, mwidth ) )
			return( -1 );
	}
	else if( vips_isprefix( "#LRROTSCALE ", line ) ||
		vips_isprefix( "#TBROTSCALE ", line ) ) {
		/* Rot + scale. Format is eg.

			#LRROTSCALE <left> <right> <out> \
				<a> <b> <x> <y> [<mwidth>]

		 */
		char *item[MAX_ITEMS];
		int nitems;
		JoinType type;
		JoinNode *arg1, *arg2, *join;
		double a, b, dx, dy;
		int mwidth;

		if( (nitems = break_items( line, item )) < 0 )
			return( -1 );
		if( nitems != 7 && nitems != 8 ) {
			vips_error( "global_balance", 
				"%s", _( "bad number of args in join1 line" ) );
			return( -1 );
		}

		if( !(arg1 = add_node( st, item[0] )) ||
			!(arg2 = add_node( st, item[1] )) ||
			!(join = add_node( st, item[2] )) )
			return( -1 );
		a = g_ascii_strtod( item[3], NULL );
		b = g_ascii_strtod( item[4], NULL );
		dx = g_ascii_strtod( item[5], NULL );
		dy = g_ascii_strtod( item[6], NULL );
		if( nitems == 8 )
			mwidth = atoi( item[7] );
		else
			mwidth = -1;
		if( vips_isprefix( "#LRROTSCALE ", line ) )
			type = JOIN_LRROTSCALE;
		else
			type = JOIN_TBROTSCALE;

		if( make_join( st, type, arg1, arg2, 
			join, a, b, dx, dy, mwidth ) )
			return( -1 );
	}
	else if( vips_isprefix( "copy ", line ) ) {
		/* vips_copy() call ... make a JOIN_CP node.
		 */
		char *item[MAX_ITEMS];
		int nitems;
		JoinNode *before, *after;

		if( (nitems = break_items( line, item )) < 0 )
			return( -1 );
		if( nitems != 2 ) {
			vips_error( "global_balance", 
				"%s", _( "bad number of args in copy line" ) );
			return( -1 );
		}

		if( !(before = add_node( st, item[0] )) ||
			!(after = add_node( st, item[1] )) ||
			make_copy( st, before, after ) )
			return( -1 );
	}

	return( 0 );
}

/* Set the dirty flag on any nodes we reference.
 */
static void *
set_referenced( JoinNode *node, void *a, void *b )
{
	if( node->arg1 )
		node->arg1->dirty = 1;
	if( node->arg2 )
		node->arg2->dirty = 1;
	
	return( NULL );
}

/* Is this a root node? Should be clean.
 */
static void *
is_root( JoinNode *node, void *a, void *b )
{
	if( !node->dirty )
		return( (void *) node );
	else
		return( NULL );
}

/* Scan the symbol table, looking for a node which no node references.
 */
static JoinNode *
find_root( SymbolTable *st )
{
	JoinNode *root;

	/* Clean the table, then scan it, setting all pointed-to nodes dirty.
	 */
	clean_table( st );
	vips__map_table( st, (VipsSListMap2Fn) set_referenced, NULL, NULL );

	/* Look for the first clean symbol.
	 */
	root = (JoinNode *) vips__map_table( st, 
		(VipsSListMap2Fn) is_root, NULL, NULL );

	/* No root? Hot dang!
	 */
	if( !root ) {
		vips_error( "vips_global_balance", 
			"%s", _( "mosaic root not found in desc file\n"
			"is this really a mosaiced image?" ) );
		return( NULL );
	}

	/* Now dirty that - then if there are any more clean symbols, we have
	 * more than one root.
	 */
	root->dirty = 1;
	if( vips__map_table( st, (VipsSListMap2Fn) is_root, NULL, NULL ) ) {
		vips_error( "vips_global_balance", 
			"%s", _( "more than one root" ) );
		return( NULL );
	}

	return( root );
}

/* Walk history_list and parse each line.
 */
int
vips__parse_desc( SymbolTable *st, VipsImage *in )
{
	GSList *p;

	for( p = in->history_list; p; p = p->next ) {
		GValue *value = (GValue *) p->data;

		g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_REF_STRING );

		if( process_line( st, vips_value_get_ref_string( value, NULL ) ) )
			return( -1 );
	}

	/* Find root.
	 */
	if( !(st->root = find_root( st )) )
		return( -1 );

	return( 0 );
}

/* Count and index all leaf images.
 */
static void *
count_leaves( JoinNode *node, void *a, void *b )
{
	if( node->type == JOIN_LEAF ) {
		node->index = node->st->nim;
		node->st->nim++;
	}

	return( NULL );
}

#ifdef DEBUG
/* Print a JoinNode.
 */
static void
print_node( JoinNode *node )
{
	char *basename = g_path_get_basename( node->name );
	printf( "%s, position %dx%d, size %dx%d, index %d\n",
		basename,
		node->cumtrn.oarea.left, node->cumtrn.oarea.top,
		node->cumtrn.oarea.width, node->cumtrn.oarea.height,
		node->index );
	g_free( basename );
}
#endif /*DEBUG*/

#ifdef DEBUG
/* Print a leaf.
 */
static void *
print_leaf( JoinNode *node, void *a, void *b )
{
	if( node->type == JOIN_LEAF ) 
		print_node( node );

	return( NULL );
}
#endif /*DEBUG*/

/* Count all join nodes.
 */
static void *
count_joins( JoinNode *node, void *a, void *b )
{
	if( node->type == JOIN_TB ||
		node->type == JOIN_LR ||
		node->type == JOIN_LRROTSCALE ||
		node->type == JOIN_TBROTSCALE )
		node->st->njoin++;

	return( NULL );
}

#ifdef DEBUG
/* Print a few spaces.
 */
static void
spc( int n )
{
	int i;

	for( i = 0; i < n; i++ )
		printf( " " );
}
#endif /*DEBUG*/

#ifdef DEBUG
static char *
JoinType2char( JoinType type )
{
	switch( type ) {
	case JOIN_LR: 		return( "JOIN_LR" );
	case JOIN_TB: 		return( "JOIN_TB" );
	case JOIN_LRROTSCALE: 	return( "JOIN_LRROTSCALE" );
	case JOIN_TBROTSCALE: 	return( "JOIN_TBROTSCALE" );
	case JOIN_CP: 		return( "JOIN_CP" );
	case JOIN_LEAF: 	return( "JOIN_LEAF" );

	default:
		vips_error_exit( "internal error #9275" );
		/*NOTEACHED*/

		return( NULL );
	}
}
#endif /*DEBUG*/

#ifdef DEBUG
/* Print a join node.
 */
static void *
print_joins( JoinNode *node, int indent )
{
	char *basename = g_path_get_basename( node->name );

	switch( node->type ) {
	case JOIN_TB:
	case JOIN_LR:
	case JOIN_TBROTSCALE:
	case JOIN_LRROTSCALE:
		spc( indent );
		printf( "%s to make %s, size %dx%d, pos. %dx%d, of:\n", 
			JoinType2char( node->type ), 
			basename,
			node->cumtrn.oarea.width, node->cumtrn.oarea.height,
			node->cumtrn.oarea.left, node->cumtrn.oarea.top );
		spc( indent );
		printf( "reference:\n" );
		print_joins( node->arg1, indent + 2 );
		spc( indent );
		printf( "secondary:\n" );
		print_joins( node->arg2, indent + 2 );
		break;

	case JOIN_CP:
		spc( indent );
		printf( "copy to make %s of:\n", basename );
		print_joins( node->arg1, indent + 2 );
		break;

	case JOIN_LEAF:
		spc( indent );
		printf( "input image %s\n", basename );
		break;
	}

	g_free( basename );

	return( NULL );
}
#endif /*DEBUG*/

#ifdef DEBUG
/* Print an overlap.
 */
static void *
print_overlap( OverlapInfo *lap, void *a, void *b )
{
	char *basename_node = g_path_get_basename( lap->node->name );
	char *basename_other = g_path_get_basename( lap->other->name );
	
	printf( "-> %s overlaps with %s; (this, other) = (%.4G, %.4G)\n",
		basename_node,
		basename_other,
		*VIPS_MATRIX( lap->nstats, 4, 0 ),
		*VIPS_MATRIX( lap->ostats, 4, 0 ) );

	g_free( basename_node );
	g_free( basename_other );
	
	return( NULL );
}
#endif /*DEBUG*/

#ifdef DEBUG
/* Print the overlaps on a leaf.
 */
static void *
print_overlaps( JoinNode *node, void *a, void *b )
{
	char *basename;
	
	if( node->type == JOIN_LEAF && g_slist_length( node->overlaps ) > 0 ) {
		basename = g_path_get_basename( node->name );
		printf( "overlap of %s with:\n", basename );
		g_free( basename );
		vips_slist_map2( node->overlaps, 
			(VipsSListMap2Fn) print_overlap, NULL, NULL );
	}

	return( NULL );
}
#endif /*DEBUG*/

#ifdef DEBUG
/* Print and accumulate the error on an overlap.
 */
static void *
print_overlap_error( OverlapInfo *lap, double *fac, double *total )
{
	char *basename_other = g_path_get_basename( lap->other->name );
	double na = *VIPS_MATRIX( lap->nstats, 4, 0 );
	double oa = *VIPS_MATRIX( lap->ostats, 4, 0 );
	double err;

	if( fac ) {
		na *= fac[lap->node->index];
		oa *= fac[lap->other->index];
	}

	err = na - oa;

	printf( "-> file %s, error = %g\n",
		basename_other, err );
	*total += err * err;
	
	g_free( basename_other );

	return( NULL );
}
#endif /*DEBUG*/

#ifdef DEBUG
/* Print and accumulate the overlap errors on a leaf.
 */
static void *
print_overlap_errors( JoinNode *node, double *fac, double *total )
{
	char *basename;
	
	if( node->type == JOIN_LEAF && g_slist_length( node->overlaps ) > 0 ) {
		basename = g_path_get_basename( node->name );
		printf( "overlap of %s (index %d) with:\n", basename, 
			node->index );
		g_free( basename );
		vips_slist_map2( node->overlaps, 
			(VipsSListMap2Fn) print_overlap_error, fac, total );
	}

	return( NULL );
}
#endif /*DEBUG*/

/* Extract a rect.
 */
static int
extract_rect( VipsImage *in, VipsImage **out, VipsRect *r )
{
	return( vips_extract_area( in, out, 
		r->left, r->top, r->width, r->height, NULL ) );
}

/* Two images overlap in an area ... make a mask the size of the area, which
 * has 255 for every pixel where both images are non-zero.
 */
static int
make_overlap_mask( VipsImage *mem, 
	VipsImage *ref, VipsImage *sec, VipsImage **mask, 
	VipsRect *rarea, VipsRect *sarea )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( mem ), 6 );

	if( extract_rect( ref, &t[0], rarea ) ||
		extract_rect( sec, &t[1], sarea ) ||
		vips_extract_band( t[0], &t[2], 0, NULL ) ||
		vips_extract_band( t[1], &t[3], 0, NULL ) ||
		vips_notequal_const1( t[2], &t[4], 0.0, NULL ) ||
		vips_notequal_const1( t[3], &t[5], 0.0, NULL ) ||
		vips_andimage( t[4], t[5], mask, NULL ) ) 
		return( -1 );

	return( 0 );
}

/* Find the number of non-zero pixels in a mask image.
 */
static int
count_nonzero( VipsImage *in, gint64 *count )
{
	double avg;

	if( vips_avg( in, &avg, NULL ) )
		return( -1 );
	*count = (avg * VIPS_IMAGE_N_PELS( in )) / 255.0;

	return( 0 );
}

/* Find stats on an area of an IMAGE ... consider only pixels for which the
 * mask is true.
 */
static VipsImage *
find_image_stats( VipsImage *mem, 
	VipsImage *in, VipsImage *mask, VipsRect *area )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( mem ), 5 );

	gint64 count;

	/* Extract area, build black image, mask out pixels we want.
	 */
	if( extract_rect( in, &t[0], area ) ||
		vips_black( &t[1], t[0]->Xsize, t[0]->Ysize, 
			"bands", t[0]->Bands, 
			NULL ) ||
		vips_cast( t[1], &t[2], t[0]->BandFmt, NULL ) ||
		vips_ifthenelse( mask, t[0], t[2], &t[3], NULL ) )
		return( NULL );

	/* Get stats from masked image.
	 */
	if( vips_stats( t[3], &t[4], NULL ) )
		return( NULL );

	/* Number of non-zero pixels in mask.
	 */
	if( count_nonzero( mask, &count ) )
		return( NULL );

	/* And scale masked average to match.
	 */
	*VIPS_MATRIX( t[4], 4, 0 ) *= 
		(double) count / VIPS_IMAGE_N_PELS( mask );

	/* Yuk! Zap the deviation column with the pixel count. Used later to
	 * determine if this is likely to be a significant overlap.
	 */
	*VIPS_MATRIX( t[4], 5, 0 )  = count;

#ifdef DEBUG
	if( count == 0 )
		g_warning( "global_balance %s", _( "empty overlap!" ) );
#endif /*DEBUG*/

	return( t[4] );
}

/* Find the stats for an overlap struct.
 */
static int
find_overlap_stats( OverlapInfo *lap )
{
	VipsImage *mem = lap->node->st->im;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( mem ), 1 );

	VipsRect rarea, sarea;

	/* Translate the overlap area into the coordinate scheme for the main
	 * node.
	 */
	rarea = lap->overlap;
	rarea.left -= lap->node->cumtrn.oarea.left;
	rarea.top -= lap->node->cumtrn.oarea.top;

	/* Translate the overlap area into the coordinate scheme for the other
	 * node.
	 */
	sarea = lap->overlap;
	sarea.left -= lap->other->cumtrn.oarea.left;
	sarea.top -= lap->other->cumtrn.oarea.top;

	/* Make a mask for the overlap.
	 */
	if( make_overlap_mask( mem, 
		lap->node->trnim, lap->other->trnim, &t[0], &rarea, &sarea ) )
		return( -1 );

	/* Find stats for that area.
	 */
	if( !(lap->nstats = find_image_stats( mem, 
		lap->node->trnim, t[0], &rarea )) )
		return( -1 );
	if( !(lap->ostats = find_image_stats( mem, 
		lap->other->trnim, t[0], &sarea )) )
		return( -1 );

	return( 0 );
}

/* Sub-fn. of below.
 */
static void *
overlap_eq( OverlapInfo *this, JoinNode *node, void *b )
{
	if( this->other == node )
		return( this );
	else
		return( NULL );
}

/* Is this an overlapping leaf? If yes, add to overlap list.
 */
static void *
test_overlap( JoinNode *other, JoinNode *node, void *b )
{
	VipsRect overlap;
	OverlapInfo *lap;

	/* Is other a suitable leaf to overlap with node?
	 */
	if( other->type != JOIN_LEAF || node == other ) 
		return( NULL );

	/* Is there an overlap?
	 */
	vips_rect_intersectrect( &node->cumtrn.oarea, &other->cumtrn.oarea, 
		&overlap );
	if( vips_rect_isempty( &overlap ) ) 
		return( NULL );

	/* Is this a trivial overlap? Ignore it if it is.
	 */
	if( overlap.width * overlap.height < TRIVIAL )
		/* Too few pixels.
		 */
		return( NULL );

	/* Have we already added this overlap the other way around? ie. is 
	 * node on other's overlap list?
	 */
	if( vips_slist_map2( other->overlaps, 
		(VipsSListMap2Fn) overlap_eq, node, NULL ) )
		return( NULL );

	/* A new overlap - add to overlap list.
	 */
	if( !(lap = build_overlap( node, other, &overlap )) )
		return( node );

	/* Calculate overlap statistics. Open stuff relative to this, and 
	 * free quickly.
	 */
	if( find_overlap_stats( lap ) ) 
		return( node );

	/* If the pixel count either masked overlap is trivial, ignore this
	 * overlap.
	 */
	if( *VIPS_MATRIX( lap->nstats, 5, 0 ) < TRIVIAL ||
		*VIPS_MATRIX( lap->ostats, 5, 0 ) < TRIVIAL ) {
#ifdef DEBUG
		printf( "trivial overlap ... junking\n" );
		printf( "nstats count = %g, ostats count = %g\n",
			*VIPS_MATRIX( lap->nstats, 5, 0 ), *VIPS_MATRIX( lap->ostats, 5, 0 ) );
		print_overlap( lap, NULL, NULL );
#endif /*DEBUG*/
		overlap_destroy( lap );
	}

	return( NULL );
}

/* If this is a leaf, look at all other joins for a leaf that overlaps. Aside:
 * If this is a leaf, there should be an IMAGE. Flag an error if there is
 * not.
 */
static void *
find_overlaps( JoinNode *node, SymbolTable *st, void *b )
{
	if( node->type == JOIN_LEAF ) {
		/* Check for image.
		 */
		if( !node->im ) {
			vips_error( "vips_global_balance", 
				_( "unable to open \"%s\"" ), node->name );
			return( node );
		}
		if( !node->trnim ) 
			vips_error_exit( "global_balance: sanity failure #9834" );

		return( vips__map_table( st, 
			(VipsSListMap2Fn) test_overlap, node, NULL ) );
	}
	
	return( NULL );
}

/* Bundle of variables for matrix creation.
 */
typedef struct {
	SymbolTable *st;		/* Main table */
	JoinNode *leaf;			/* Leaf to be 1.000 */
	VipsImage *K;			/* LHS */
	VipsImage *M;			/* RHS */
	int row;			/* Current row */
} MatrixBundle;

/* Add a new row for the nominated overlap to the matrices.
 */
static void *
add_nominated( OverlapInfo *ovl, MatrixBundle *bun, double *gamma )
{
	double ns = pow( *VIPS_MATRIX( ovl->nstats, 4, 0 ), 1.0 / (*gamma) );
	double os = pow( *VIPS_MATRIX( ovl->ostats, 4, 0 ), 1.0 / (*gamma) );

	*VIPS_MATRIX( bun->K, 0, bun->row ) = ns;
	*VIPS_MATRIX( bun->M, ovl->other->index - 1, bun->row ) = os;

	bun->row++;

	return( NULL );
}

/* Add a new row for an ordinary overlap to the matrices.
 */
static void *
add_other( OverlapInfo *ovl, MatrixBundle *bun, double *gamma )
{
	double ns = -pow( *VIPS_MATRIX( ovl->nstats, 4, 0 ), 1.0 / (*gamma) );
	double os = pow( *VIPS_MATRIX( ovl->ostats, 4, 0 ), 1.0 / (*gamma) );

	*VIPS_MATRIX( bun->M, ovl->node->index - 1, bun->row ) = ns;
	*VIPS_MATRIX( bun->M, ovl->other->index - 1, bun->row ) = os;

	bun->row++;

	return( NULL );
}

/* Add stuff for node to matrix.
 */
static void *
add_row( JoinNode *node, MatrixBundle *bun, double *gamma )
{
	if( node == bun->leaf )
		vips_slist_map2( node->overlaps, 
			(VipsSListMap2Fn) add_nominated, bun, gamma );
	else
		vips_slist_map2( node->overlaps, 
			(VipsSListMap2Fn) add_other, bun, gamma );
	
	return( NULL );
}

/* Fill K and M. leaf is image selected to have factor of 1.000.
 */
static void
fill_matrices( SymbolTable *st, double gamma, VipsImage *K, VipsImage *M )
{
	MatrixBundle bun;

	bun.st = st;
	bun.leaf = st->leaf;
	bun.K = K;
	bun.M = M;
	bun.row = 0;

	/* Build matrices.
	 */
	vips__map_table( st, (VipsSListMap2Fn) add_row, &bun, &gamma );
}

/* Used to select the leaf whose coefficient we set to 1.
 */
static void *
choose_leaf( JoinNode *node, void *a, void *b )
{
	if( node->type == JOIN_LEAF )
		return( node );
	
	return( NULL );
}

/* Make an image from a node.
 */
static VipsImage *
make_mos_image( SymbolTable *st, JoinNode *node, transform_fn tfn, void *a )
{
	VipsImage *im1, *im2, *out;

	switch( node->type ) {
	case JOIN_LR:
	case JOIN_TB:
		if( !(im1 = make_mos_image( st, node->arg1, tfn, a )) ||
			!(im2 = make_mos_image( st, node->arg2, tfn, a )) )
			return( NULL );

		if( vips_merge( im1, im2, &out, 
			node->type == JOIN_LR ? 
				VIPS_DIRECTION_HORIZONTAL : 
				VIPS_DIRECTION_VERTICAL,
			-node->dx, -node->dy, 
			"mblend", node->mwidth,
			NULL ) )
			return( NULL );
		vips_object_local( st->im, out );
		vips_image_set_string( out, "mosaic-name", node->name );

		break;

	case JOIN_LRROTSCALE:
	case JOIN_TBROTSCALE:
		if( !(im1 = make_mos_image( st, node->arg1, tfn, a )) ||
			!(im2 = make_mos_image( st, node->arg2, tfn, a )) )
			return( NULL );

		out = vips_image_new();
		vips_object_local( st->im, out );

		vips_image_set_string( out, "mosaic-name", node->name );

		if( node->type == JOIN_LRROTSCALE ) {
			if( vips__lrmerge1( im1, im2, out, 
				node->a, node->b, node->dx, node->dy,
				node->mwidth ) )
				return( NULL );
		}
		else {
			if( vips__tbmerge1( im1, im2, out, 
				node->a, node->b, node->dx, node->dy,
				node->mwidth ) )
				return( NULL );
		}

		break;

	case JOIN_LEAF:
		/* Trivial case!
		 */
		if( !(out = tfn( node, a )) )
			return( NULL );

		break;

	case JOIN_CP:
		/* Very trivial case.
		 */
		out = make_mos_image( st, node->arg1, tfn, a );

		break;

	default:
		vips_error_exit( "internal error #982369824375987" );
		/*NOTEACHED*/
		return( NULL );
	}

	return( out );
}

/* Re-build mosaic. 
 */
int
vips__build_mosaic( SymbolTable *st, VipsImage *out, transform_fn tfn, void *a )
{
	JoinNode *root = st->root;
	VipsImage *im1, *im2;
	VipsImage *x;

	switch( root->type ) {
	case JOIN_LR:
	case JOIN_TB:
		if( !(im1 = make_mos_image( st, root->arg1, tfn, a )) ||
			!(im2 = make_mos_image( st, root->arg2, tfn, a )) )
			return( -1 );

		if( vips_merge( im1, im2, &x, 
			root->type == JOIN_LR ? 
				VIPS_DIRECTION_HORIZONTAL : 
				VIPS_DIRECTION_VERTICAL,
			-root->dx, -root->dy, 
			"mblend", root->mwidth,
			NULL ) )
			return( -1 );
		if( vips_image_write( x, out ) ) {
			g_object_unref( x );
			return( -1 );
		}
		g_object_unref( x );

		break;

	case JOIN_LRROTSCALE:
	case JOIN_TBROTSCALE:
		if( !(im1 = make_mos_image( st, root->arg1, tfn, a )) ||
			!(im2 = make_mos_image( st, root->arg2, tfn, a )) )
			return( -1 );

		if( root->type == JOIN_LRROTSCALE ) {
			if( vips__lrmerge1( im1, im2, out, 
				root->a, root->b, root->dx, root->dy,
				root->mwidth ) )
				return( -1 );
		}
		else {
			if( vips__tbmerge1( im1, im2, out, 
				root->a, root->b, root->dx, root->dy,
				root->mwidth ) )
				return( -1 );
		}

		break;

	case JOIN_LEAF:
		/* Trivial case! Just one file in our mosaic.
		 */
		if( !(im1 = tfn( root, a )) || 
			vips_image_write( im1, out ) )
			return( -1 );

		break;

	case JOIN_CP:
		/* Very trivial case.
		 */
		if( !(im1 = make_mos_image( st, root->arg1, tfn, a )) ||
			vips_image_write( im1, out ) )
			return( -1 );

		break;

	default:
		vips_error_exit( "internal error #982369824375987" );
		/*NOTEACHED*/
	}

	return( 0 );
}

static int
vips__matrixtranspose( VipsImage *in, VipsImage **out )
{
	int yc, xc;

	/* Allocate output matrix.
	 */
	if( !(*out = vips_image_new_matrix( in->Ysize, in->Xsize )) )
		return( -1 );

	/* Transpose.
	 */
	for( yc = 0; yc < (*out)->Ysize; ++yc )
		for( xc = 0; xc < (*out)->Xsize; ++xc )
			*VIPS_MATRIX( *out, xc, yc ) = *VIPS_MATRIX( in, yc, xc );

	return( 0 );
}

static int
vips__matrixmultiply( VipsImage *in1, VipsImage *in2, VipsImage **out )
{
	int xc, yc, col;
	double sum;
	double *mat, *a, *b;
	double *s1, *s2;

	/* Check matrix sizes.
	 */
	if( in1->Xsize != in2->Ysize ) {
		vips_error( "vips__matrixmultiply", "%s", _( "bad sizes" ) );
		return( -1 );
	}

	/* Allocate output matrix.
	 */
	if( !(*out = vips_image_new_matrix( in2->Xsize, in1->Ysize  )) )
		return( -1 );

	/* Multiply.
	 */
	mat = VIPS_MATRIX( *out, 0, 0 );
	s1 = VIPS_MATRIX( in1, 0, 0 );

	for( yc = 0; yc < in1->Ysize; yc++ ) {
		s2 = VIPS_MATRIX( in2, 0, 0 );

		for( col = 0; col < in2->Xsize; col++ ) {
			/* Get ready to sweep a row.
			 */
			a = s1;
			b = s2;

			for( sum = 0.0, xc = 0; xc < in1->Xsize; xc++ ) {
				sum += *a++ * *b;
				b += in2->Xsize;
			}

			*mat++ = sum;
			s2++;
		}

		s1 += in1->Xsize;
	}

	return( 0 );
}

/* Find correction factors.
 */
static int
find_factors( SymbolTable *st, double gamma )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( st->im ), 7 );

	double total;
	double avg;
	int i;

	/* Make output matrices.
	 */
	if( !(t[0] = vips_image_new_matrix( 1, st->novl )) ||
		!(t[1] = vips_image_new_matrix( st->nim - 1, st->novl )) )
		return( -1 );

	fill_matrices( st, gamma, t[0], t[1] );

#ifdef DEBUG
	vips_image_write_to_file( t[0], "K.mat", NULL ); 
	vips_image_write_to_file( t[1], "M.mat", NULL );
#endif /*DEBUG*/

	/* Calculate LMS.
	 */
	if( vips__matrixtranspose( t[1], &t[2] ) ||
		vips__matrixmultiply( t[2], t[1], &t[3] ) ||
		vips_matrixinvert( t[3], &t[4], NULL ) ||
		vips__matrixmultiply( t[4], t[2], &t[5] ) ||
		vips__matrixmultiply( t[5], t[0], &t[6] ) )
		return( -1 );

	/* Make array of correction factors.
	 */
	if( !(st->fac = VIPS_ARRAY( st->im, st->nim, double )) )
		return( -1 );
	for( i = 0; i < t[6]->Ysize; i++ )
		st->fac[i + 1] = *VIPS_MATRIX( t[6], 0, i );
	st->fac[0] = 1.0;

	/* Find average balance factor, normalise to that average.
	 */
	total = 0.0;
	for( i = 0; i < st->nim; i++ )
		total += st->fac[i];
	avg = total / st->nim;
	for( i = 0; i < st->nim; i++ )
		st->fac[i] /= avg;

#ifdef DEBUG
	/* Diagnostics!
	 */
	printf( "debugging output for vips_global_balance():\n" );
	for( i = 0; i < st->nim; i++ )
		printf( "balance factor %d = %g\n", i, st->fac[i] );
	total = 0.0;
	printf( "Overlap errors:\n" );
	vips__map_table( st, 
		(VipsSListMap2Fn) print_overlap_errors, NULL, &total );
	printf( "RMS error = %g\n", sqrt( total / st->novl ) );

	total = 0.0;
	printf( "Overlap errors after adjustment:\n" );
	vips__map_table( st, 
		(VipsSListMap2Fn) print_overlap_errors, st->fac, &total );
	printf( "RMS error = %g\n", sqrt( total / st->novl ) );
#endif /*DEBUG*/

	return( 0 );
}

/* TODO(kleisauke): Copied from im__affinei */
/* Shared with vips_mosaic1(), so not static. */
int
vips__affinei( VipsImage *in, VipsImage *out, VipsTransformation *trn )
{
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( out ), 2 );
	VipsArrayInt *oarea;
	gboolean repack;

	oarea = vips_array_int_newv( 4,
		trn->oarea.left, trn->oarea.top,
		trn->oarea.width, trn->oarea.height );

	/* vips7 affine would repack labq and im_benchmark() depends upon
	 * this.
	 */
	repack = in->Coding == VIPS_CODING_LABQ;

	if( vips_affine( in, &t[0],
		trn->a, trn->b, trn->c, trn->d,
		"oarea", oarea,
		"odx", trn->odx,
		"ody", trn->ody,
		NULL ) ) {
		vips_area_unref( VIPS_AREA( oarea ) );
		return( -1 );
	}
	vips_area_unref( VIPS_AREA( oarea ) );
	in = t[0];

	if( repack ) {
		if (vips_colourspace( in, &t[1],
			VIPS_INTERPRETATION_LABQ, NULL ) )
			return ( -1 );
		in = t[1];
	}

	if( vips_image_write( in, out ) )
		return( -1 );

	return( 0 );
}

/* Look for all leaves, make sure we have a transformed version of each.
 */
static void *
generate_trn_leaves( JoinNode *node, SymbolTable *st, void *b )
{
	if( node->type == JOIN_LEAF ) {
		/* Check for image.
		 */
		if( !node->im ) {
			vips_error( "vips_global_balance", 
				_( "unable to open \"%s\"" ), node->name );
			return( node );
		}
		if( node->trnim ) 
			vips_error_exit( "global_balance: sanity failure #765" );

		/* Special case: if this is an untransformed leaf (there will
		 * always be at least one), then skip the affine.
		 */
		if( vips__transform_isidentity( &node->cumtrn ) )
			node->trnim = node->im;
		else {
			node->trnim = vips_image_new();
			vips_object_local( node->st->im, node->trnim );

			if ( vips__affinei( node->im, node->trnim, &node->cumtrn ) )
				return( node );
		}
	}

	return( NULL );
}

/* Analyse mosaic.
 */
static int
analyse_mosaic( SymbolTable *st, VipsImage *in )
{
	/* Parse Hist on in.
	 */
	if( vips__parse_desc( st, in ) )
		return( -1 );

	/* Print parsed data.
	 */
#ifdef DEBUG
	printf( "Input files:\n" );
	vips__map_table( st, (VipsSListMap2Fn) print_leaf, NULL, NULL );
	printf( "\nOutput file:\n" );
	print_node( st->root );
	printf( "\nJoin commands:\n" );
	print_joins( st->root, 0 );
#endif /*DEBUG*/

	/* Generate transformed leaves.
	 */
	if( vips__map_table( st, 
		(VipsSListMap2Fn) generate_trn_leaves, st, NULL ) )
		return( -1 );

	/* Find overlaps.
	 */
	if( vips__map_table( st, (VipsSListMap2Fn) find_overlaps, st, NULL ) )
		return( -1 );

	/* Scan table, counting and indexing input images and joins. 
	 */
	vips__map_table( st, (VipsSListMap2Fn) count_leaves, NULL, NULL );
	vips__map_table( st, (VipsSListMap2Fn) count_joins, NULL, NULL );

	/* Select leaf to be 1.000.
	 * This must be index == 0, unless you change stuff above!
	 */
	st->leaf = vips__map_table( st, 
		(VipsSListMap2Fn) choose_leaf, NULL, NULL );

	/* And print overlaps.
	 */
#ifdef DEBUG
	printf( "\nLeaf to be 1.000:\n" );
	print_node( st->leaf );
	printf( "\nOverlaps:\n" );
	vips__map_table( st, (VipsSListMap2Fn) print_overlaps, NULL, NULL );
	printf( "\n%d input files, %d unique overlaps, %d joins\n", 
		st->nim, st->novl, st->njoin );
#endif /*DEBUG*/

	return( 0 );
}

/* Scale im by fac --- if it's uchar/ushort, use a lut. If we can use a lut,
 * transform in linear space. If we can't, don't bother for efficiency.
 */
static VipsImage *
transform( JoinNode *node, double *gamma )
{
	SymbolTable *st = node->st;
	VipsImage *in = node->im;
	double fac = st->fac[node->index];
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( st->im ), 8 );

	VipsImage *out;

	if( fac == 1.0 ) {
		/* Easy!
		 */
		out = in;
	}
	/* TODO(kleisauke): Could we call vips_gamma instead? 
	 */
	else if( in->BandFmt == VIPS_FORMAT_UCHAR || 
		in->BandFmt == VIPS_FORMAT_USHORT ) {
		if( vips_identity( &t[0],
				"bands", 1,
				"ushort", in->BandFmt == VIPS_FORMAT_USHORT,
				//"size", 65535,
				NULL ) ||
			vips_pow_const1( t[0], &t[1],
				1.0 / (*gamma), NULL ) ||
			vips_linear1( t[1], &t[2], fac, 0.0, NULL ) ||
			vips_pow_const1( t[2], &t[3], *gamma, NULL ) ||
			vips_cast( t[3], &t[4], in->BandFmt, NULL ) ||
			vips_maplut( in, &t[5], t[4], NULL ) )
			return( NULL );
		out = t[5];
	}
	else {
		/* Just vips_linear1 it.
		 */
		if( vips_linear1( in, &t[6], fac, 0.0, NULL ) ||
			vips_cast( t[6], &t[7], in->BandFmt, NULL ) )
			return( NULL );
		out = t[7];
	}

	vips_image_set_string( out, "mosaic-name", node->name );

	return( out );
}

/* As above, but output as float, not matched to input.
 */
static VipsImage *
transformf( JoinNode *node, double *gamma )
{
	SymbolTable *st = node->st;
	VipsImage *in = node->im;
	double fac = node->st->fac[node->index];
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( st->im ), 6 );

	VipsImage *out;

	if( fac == 1.0 ) {
		/* Easy!
		 */
		out = in;
	}
	else if( in->BandFmt == VIPS_FORMAT_UCHAR || 
		in->BandFmt == VIPS_FORMAT_USHORT ) {
		if( vips_identity( &t[0],
				"bands", 1,
				"ushort", in->BandFmt == VIPS_FORMAT_USHORT,
				//"size", 65535,
				NULL ) ||
			vips_pow_const1( t[0], &t[1],
				1.0 / (*gamma), NULL ) ||
			vips_linear1( t[1], &t[2], fac, 0.0, NULL ) ||
			vips_pow_const1( t[2], &t[3], *gamma, NULL ) ||
			vips_maplut( in, &t[4], t[3], NULL ) )
			return( NULL );
		out = t[4];
	}
	else {
		/* Just vips_linear1 it.
		 */
		if( vips_linear1( in, &t[5], fac, 0.0, NULL ) )
			return( NULL );
		out = t[5];
	}

	vips_image_set_string( out, "mosaic-name", node->name );

	return( out );
}

typedef struct {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	gboolean int_output;
	double gamma;

} VipsGlobalbalance;

typedef VipsOperationClass VipsGlobalbalanceClass;

G_DEFINE_TYPE( VipsGlobalbalance, vips_globalbalance, VIPS_TYPE_OPERATION );

static int
vips_globalbalance_build( VipsObject *object )
{
	VipsGlobalbalance *globalbalance = (VipsGlobalbalance *) object;

	SymbolTable *st;
	transform_fn trn;

	g_object_set( globalbalance, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_globalbalance_parent_class )->
		build( object ) )
		return( -1 );

	if( !(st = vips__build_symtab( globalbalance->out, SYM_TAB_SIZE )) ||
		analyse_mosaic( st, globalbalance->in ) ||
		find_factors( st, globalbalance->gamma ) )
		return( -1 );

	trn = globalbalance->int_output ? 
		(transform_fn) transform : (transform_fn) transformf; 
	if( vips__build_mosaic( st, globalbalance->out, 
		trn, &globalbalance->gamma ) )
		return( -1 );

	return( 0 );
}

static void
vips_globalbalance_class_init( VipsGlobalbalanceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "globalbalance";
	object_class->description = _( "global balance an image mosaic" );
	object_class->build = vips_globalbalance_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsGlobalbalance, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsGlobalbalance, out ) );

	VIPS_ARG_DOUBLE( class, "gamma", 5, 
		_( "Gamma" ), 
		_( "Image gamma" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGlobalbalance, gamma ),
		0.00001, 10, 1.6 );

	VIPS_ARG_BOOL( class, "int_output", 7, 
		_( "Int output" ), 
		_( "Integer output" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGlobalbalance, int_output ),
		FALSE ); 

}

static void
vips_globalbalance_init( VipsGlobalbalance *globalbalance )
{
	globalbalance->gamma = 1.6;
}

/**
 * vips_globalbalance: (method)
 * @in: mosaic to rebuild
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 * 
 * Optional arguments:
 *
 * * @gamma: gamma of source images
 * * @int_output: %TRUE for integer image output
 *
 * vips_globalbalance() can be used to remove contrast differences in 
 * an assembled mosaic.
 *
 * It reads the History field attached to @in and builds a list of the source
 * images that were used to make the mosaic and the position that each ended
 * up at in the final image.
 *
 * It opens each of the source images in turn and extracts all parts which
 * overlap with any of the other images. It finds the average values in the
 * overlap areas and uses least-mean-square to find a set of correction
 * factors which will minimise overlap differences. It uses @gamma to
 * gamma-correct the source images before calculating the factors. A value of
 * 1.0 will stop this.
 *
 * Each of the source images is transformed with the appropriate correction 
 * factor, then the mosaic is reassembled. @out is #VIPS_FORMAT_FLOAT, but 
 * if @int_output is set, the output image is the same format as the input
 * images.  
 *
 * There are some conditions that must be met before this operation can work:
 * the source images must all be present under the filenames recorded in the
 * history on @in, and the mosaic must have been built using only operations in
 * this package.
 *
 * See also: vips_remosaic().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_globalbalance( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "globalbalance", ap, in, out );
	va_end( ap );

	return( result );
}
