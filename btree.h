/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/btree.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_BTREE_H
#define _APFS_BTREE_H

#include <linux/types.h>

struct super_block;

/* Flags for the query structure */
#define APFS_QUERY_TREE_MASK	0007	/* Which b-tree we query */
#define APFS_QUERY_OMAP		0001	/* This is a b-tree object map query */
#define APFS_QUERY_CAT		0002	/* This is a catalog tree query */
#define APFS_QUERY_NEXT		0010	/* Find next of multiple matches */
#define APFS_QUERY_EXACT	0020	/* Search for an exact match */
#define APFS_QUERY_DONE		0040	/* The search at this level is over */
#define APFS_QUERY_ANY_NAME	0100	/* Multiple search for any name */
#define APFS_QUERY_ANY_NUMBER	0200	/* Multiple search for any number */
#define APFS_QUERY_MULTIPLE	(APFS_QUERY_ANY_NAME | APFS_QUERY_ANY_NUMBER)

/*
 * Structure used to retrieve data from an APFS B-Tree. For now only used
 * on the calalog and the object map.
 */
struct apfs_query {
	struct apfs_node *node;		/* Node being searched */
	struct apfs_key *key;		/* What the query is looking for */

	struct apfs_query *parent;	/* Query for parent node */
	unsigned int flags;

	/* Set by the query on success */
	int index;			/* Index of the entry in the node */
	int key_off;			/* Offset of the key in the node */
	int key_len;			/* Length of the key */
	int off;			/* Offset of the data in the node */
	int len;			/* Length of the data */

	int depth;			/* Put a limit on recursion */
};

extern struct apfs_query *apfs_alloc_query(struct apfs_node *node,
					   struct apfs_query *parent);
extern void apfs_free_query(struct super_block *sb, struct apfs_query *query);
extern int apfs_btree_query(struct super_block *sb, struct apfs_query **query);
extern struct apfs_node *apfs_omap_read_node(struct super_block *sb, u64 id);
extern int apfs_omap_lookup_block(struct super_block *sb,
				  struct apfs_node *tbl, u64 id, u64 *block);

#endif	/* _APFS_BTREE_H */
