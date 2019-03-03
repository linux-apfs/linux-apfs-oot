// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/btree.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include "apfs.h"
#include "btree.h"
#include "key.h"
#include "message.h"
#include "node.h"
#include "super.h"

/**
 * apfs_child_from_query - Read the child id found by a successful nonleaf query
 * @query:	the query that found the record
 * @child:	Return parameter.  The child id found.
 *
 * Reads the child id in the nonleaf node record into @child and performs a
 * basic sanity check as a protection against crafted filesystems.  Returns 0
 * on success or -EFSCORRUPTED otherwise.
 */
static int apfs_child_from_query(struct apfs_query *query, u64 *child)
{
	char *raw = query->node->object.bh->b_data;

	if (query->len != 8) /* The data on a nonleaf node is the child id */
		return -EFSCORRUPTED;

	*child = le64_to_cpup((__le64 *)(raw + query->off));
	return 0;
}

/**
 * apfs_omap_lookup_block - Find the block number of a b-tree node from its id
 * @sb:		filesystem superblock
 * @tbl:	Root of the object map to be searched
 * @id:		id of the node
 * @block:	on return, the found block number
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
int apfs_omap_lookup_block(struct super_block *sb, struct apfs_node *tbl,
			   u64 id, u64 *block)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_query *query;
	struct apfs_key key;
	int ret = 0;

	query = apfs_alloc_query(tbl, NULL /* parent */);
	if (!query)
		return -ENOMEM;

	apfs_init_omap_key(id, sbi->s_xid, &key);
	query->key = &key;
	query->flags |= APFS_QUERY_OMAP;

	ret = apfs_btree_query(sb, &query);
	if (ret)
		goto fail;

	ret = apfs_bno_from_query(query, block);
	if (ret)
		apfs_alert(sb, "bad object map leaf block: 0x%llx",
			   query->node->object.block_nr);

fail:
	apfs_free_query(sb, query);
	return ret;
}

/**
 * apfs_alloc_query - Allocates a query structure
 * @node:	node to be searched
 * @parent:	query for the parent node
 *
 * Callers other than apfs_btree_query() should set @parent to NULL, and @node
 * to the root of the b-tree. They should also initialize most of the query
 * fields themselves; when @parent is not NULL the query will inherit them.
 *
 * Returns the allocated query, or NULL in case of failure.
 */
struct apfs_query *apfs_alloc_query(struct apfs_node *node,
				    struct apfs_query *parent)
{
	struct apfs_query *query;

	query = kmalloc(sizeof(*query), GFP_KERNEL);
	if (!query)
		return NULL;

	/* To be released by free_query. */
	apfs_node_get(node);
	query->node = node;
	query->key = parent ? parent->key : NULL;
	query->flags = parent ?
		parent->flags & ~(APFS_QUERY_DONE | APFS_QUERY_NEXT) : 0;
	query->parent = parent;
	/* Start the search with the last record and go backwards */
	query->index = node->records;
	query->depth = parent ? parent->depth + 1 : 0;

	return query;
}

/**
 * apfs_free_query - Free a query structure
 * @sb:		filesystem superblock
 * @query:	query to free
 *
 * Also frees the ancestor queries, if they are kept.
 */
void apfs_free_query(struct super_block *sb, struct apfs_query *query)
{
	while (query) {
		struct apfs_query *parent = query->parent;

		apfs_node_put(query->node);
		kfree(query);
		query = parent;
	}
}

/**
 * apfs_btree_query - Execute a query on a b-tree
 * @sb:		filesystem superblock
 * @query:	the query to execute
 *
 * Searches the b-tree starting at @query->index in @query->node, looking for
 * the record corresponding to @query->key.
 *
 * Returns 0 in case of success and sets the @query->len, @query->off and
 * @query->index fields to the results of the query. @query->node will now
 * point to the leaf node holding the record.
 *
 * In case of failure returns an appropriate error code.
 */
int apfs_btree_query(struct super_block *sb, struct apfs_query **query)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_node *node;
	struct apfs_query *parent;
	u64 child_id, child_blk;
	int err;

next_node:
	if ((*query)->depth >= 12) {
		/*
		 * We need a maximum depth for the tree so we can't loop
		 * forever if the filesystem is damaged. 12 should be more
		 * than enough to map every block.
		 */
		apfs_alert(sb, "b-tree is corrupted");
		return -EFSCORRUPTED;
	}

	err = apfs_node_query(sb, *query);
	if (err == -EAGAIN) {
		if (!(*query)->parent) /* We are at the root of the tree */
			return -ENODATA;

		/* Move back up one level and continue the query */
		parent = (*query)->parent;
		(*query)->parent = NULL; /* Don't free the parent */
		apfs_free_query(sb, *query);
		*query = parent;
		goto next_node;
	}
	if (err)
		return err;
	if (apfs_node_is_leaf((*query)->node)) /* All done */
		return 0;

	err = apfs_child_from_query(*query, &child_id);
	if (err) {
		apfs_alert(sb, "bad index block: 0x%llx",
			   (*query)->node->object.block_nr);
		return err;
	}

	/*
	 * The omap maps a node id into a block number. The nodes
	 * of the omap itself do not need this translation.
	 */
	if ((*query)->flags & APFS_QUERY_OMAP) {
		child_blk = child_id;
	} else {
		/*
		 * we are always performing lookup from omap root. Might
		 * need improvement in the future.
		 */
		err = apfs_omap_lookup_block(sb, sbi->s_omap_root,
					     child_id, &child_blk);
		if (err)
			return err;
	}

	/* Now go a level deeper and search the child */
	node = apfs_read_node(sb, child_blk);
	if (IS_ERR(node))
		return PTR_ERR(node);

	if (node->object.oid != child_id)
		apfs_debug(sb, "corrupt b-tree");

	if ((*query)->flags & APFS_QUERY_MULTIPLE) {
		/*
		 * We are looking for multiple entries, so we must remember
		 * the parent node and index to continue the search later.
		 */
		*query = apfs_alloc_query(node, *query);
		apfs_node_put(node);
	} else {
		/* Reuse the same query structure to search the child */
		apfs_node_put((*query)->node);
		(*query)->node = node;
		(*query)->index = node->records;
		(*query)->depth++;
	}
	goto next_node;
}

/**
 * apfs_omap_read_node - Find and read a node from a b-tree
 * @id:		id for the seeked node
 *
 * Returns NULL is case of failure, otherwise a pointer to the resulting
 * apfs_node structure.
 */
struct apfs_node *apfs_omap_read_node(struct super_block *sb, u64 id)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_node *result;
	u64 block;
	int err;

	err = apfs_omap_lookup_block(sb, sbi->s_omap_root, id, &block);
	if (err)
		return ERR_PTR(err);

	result = apfs_read_node(sb, block);
	if (IS_ERR(result))
		return result;

	if (result->object.oid != id)
		apfs_debug(sb, "corrupt b-tree");

	return result;
}
