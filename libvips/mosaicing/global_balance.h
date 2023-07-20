/* Header for the .desc file parser in vips_global_balance()
 *
 * 1/11/01 JC
 *	- cut from global_balance.c
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

/* Number of entries in spine of file name hash table.
 */
#define SYM_TAB_SIZE (113)

typedef enum _JoinType JoinType;
typedef struct _OverlapInfo OverlapInfo;
typedef struct _JoinNode JoinNode;
typedef struct _SymbolTable SymbolTable;

/* Type of a transform function.
 */
typedef VipsImage *(*transform_fn)(JoinNode *, void *);

/* Join type.
 */
enum _JoinType {
	JOIN_LR,		 /* vips__lrmerge join */
	JOIN_TB,		 /* vips__tbmerge join */
	JOIN_LRROTSCALE, /* 1st order lrmerge */
	JOIN_TBROTSCALE, /* 1st order tbmerge */
	JOIN_CP,		 /* vips_copy operation */
	JOIN_LEAF		 /* Base file */
};

/* An overlap struct. Attach a list of these to each leaf, one for each of
 * the other leaves we touch.
 */
struct _OverlapInfo {
	JoinNode *node;	   /* The base node - we are on this list */
	JoinNode *other;   /* Node we overlap with */
	VipsRect overlap;  /* The overlap area */
	VipsImage *nstats; /* Node's stats for overlap area */
	VipsImage *ostats; /* Other's stats for overlap area */
};

/* Struct for a join node.
 */
struct _JoinNode {
	char *name;		 /* This file name */
	JoinType type;	 /* What kind of join */
	SymbolTable *st; /* Symbol table we are on */
	int dirty;		 /* Used for circularity detection */

	/* Params from join line in .desc file.
	 */
	double a, b;
	double dx, dy;
	int mwidth;

	/* Cumulative transform for this node. What our parents do to us.
	 * cumtrn.area is position and size of us, thistrn.area is pos and
	 * size of arg2.
	 */
	VipsTransformation cumtrn;

	/* X-tras for LR/TB. thistrn is what we do to arg2.
	 */
	JoinNode *arg1;				/* Left or up thing to join */
	JoinNode *arg2;				/* Right or down thing to join */
	VipsTransformation thistrn; /* Transformation for arg2 */

	/* Special for leaves: all the join_nodes we overlap with, the
	 * VipsImage for that file, and the index.
	 */
	GSList *overlaps;
	VipsImage *im;
	VipsImage *trnim; /* Transformed image .. used in 2nd pass */
	int index;
};

/* We need to keep a table of JoinNode, indexed by file name. Hash into one
 * of these from the name to get a pointer to the base of a list of JoinNode
 * which hash to that offset.
 */
struct _SymbolTable {
	GSList **table; /* Ptr to base of hash table */
	int sz;			/* Size of hash table */
	VipsImage *im;	/* Malloc relative to this */

	int novl;  /* Number of unique overlaps */
	int nim;   /* Number of leaf images */
	int njoin; /* Number of join nodes */

	JoinNode *root; /* Root of join tree */
	JoinNode *leaf; /* Leaf nominated to be 1.000 */
	double *fac;	/* Correction factors */
};

VipsImage *vips__global_open_image(SymbolTable *st, char *name);
SymbolTable *vips__build_symtab(VipsImage *out, int sz);
int vips__parse_desc(SymbolTable *st, VipsImage *in);
void *vips__map_table(SymbolTable *st, VipsSListMap2Fn fn, void *a, void *b);
int vips__build_mosaic(SymbolTable *st,
	VipsImage *out, transform_fn tfn, void *a);
