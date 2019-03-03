// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/node.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include "apfs.h"
#include "btree.h"
#include "key.h"
#include "message.h"
#include "node.h"
#include "object.h"
#include "super.h"

/**
 * apfs_node_is_valid - Check basic sanity of the node index
 * @sb:		filesystem superblock
 * @node:	node to check
 *
 * Verifies that the node index fits in a single block, and that the number
 * of records fits in the index. Without this check a crafted filesystem could
 * pretend to have too many records, and calls to apfs_node_locate_key() and
 * apfs_node_locate_data() would read beyond the limits of the node.
 */
static bool apfs_node_is_valid(struct super_block *sb,
			       struct apfs_node *node)
{
	int records = node->records;
	int index_size = node->key - sizeof(struct apfs_btree_node_phys);
	int entry_size;

	if (!records) /* Empty nodes could keep a multiple query spinning */
		return false;

	if (node->key > sb->s_blocksize)
		return false;

	entry_size = (apfs_node_has_fixed_kv_size(node)) ?
		sizeof(struct apfs_kvoff) : sizeof(struct apfs_kvloc);

	return records * entry_size <= index_size;
}

static void apfs_node_release(struct kref *kref)
{
	struct apfs_node *node =
		container_of(kref, struct apfs_node, refcount);

	brelse(node->object.bh);
	kfree(node);
}

void apfs_node_get(struct apfs_node *node)
{
	kref_get(&node->refcount);
}

void apfs_node_put(struct apfs_node *node)
{
	kref_put(&node->refcount, apfs_node_release);
}

/**
 * apfs_read_node - Read a node header from disk
 * @sb:		filesystem superblock
 * @block:	number of the block where the node is stored
 *
 * Returns ERR_PTR in case of failure, otherwise return a pointer to the
 * resulting apfs_node structure with the initial reference taken.
 *
 * For now we assume the node has not been read before.
 */
struct apfs_node *apfs_read_node(struct super_block *sb, u64 block)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct buffer_head *bh;
	struct apfs_btree_node_phys *raw;
	struct apfs_node *node;

	bh = sb_bread(sb, block);
	if (!bh) {
		apfs_err(sb, "unable to read node");
		return ERR_PTR(-EINVAL);
	}
	raw = (struct apfs_btree_node_phys *) bh->b_data;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		brelse(bh);
		return ERR_PTR(-ENOMEM);
	}

	node->flags = le16_to_cpu(raw->btn_flags);
	node->records = le32_to_cpu(raw->btn_nkeys);
	node->key = sizeof(*raw) + le16_to_cpu(raw->btn_table_space.off)
				+ le16_to_cpu(raw->btn_table_space.len);
	node->free = node->key + le16_to_cpu(raw->btn_free_space.off);
	node->data = node->free + le16_to_cpu(raw->btn_free_space.len);

	node->object.sb = sb;
	node->object.block_nr = block;
	node->object.oid = le64_to_cpu(raw->btn_o.o_oid);
	node->object.bh = bh;

	kref_init(&node->refcount);

	if (sbi->s_flags & APFS_CHECK_NODES &&
	    !apfs_obj_verify_csum(sb, &raw->btn_o)) {
		apfs_alert(sb, "bad checksum for node in block 0x%llx", block);
		apfs_node_put(node);
		return ERR_PTR(-EFSBADCRC);
	}
	if (!apfs_node_is_valid(sb, node)) {
		apfs_alert(sb, "bad node in block 0x%llx", block);
		apfs_node_put(node);
		return ERR_PTR(-EFSCORRUPTED);
	}

	return node;
}

/**
 * apfs_node_locate_key - Locate the key of a node record
 * @node:	node to be searched
 * @index:	number of the entry to locate
 * @off:	on return will hold the offset in the block
 *
 * Returns the length of the key, or 0 in case of failure. The function checks
 * that this length fits within the block; callers must use the returned value
 * to make sure they never operate outside its bounds.
 */
static int apfs_node_locate_key(struct apfs_node *node, int index, int *off)
{
	struct super_block *sb = node->object.sb;
	struct apfs_btree_node_phys *raw;
	int len;

	if (index >= node->records)
		return 0;

	raw = (struct apfs_btree_node_phys *)node->object.bh->b_data;
	if (apfs_node_has_fixed_kv_size(node)) {
		struct apfs_kvoff *entry;

		entry = (struct apfs_kvoff *)raw->btn_data + index;
		len = 16;
		/* Translate offset in key area to offset in block */
		*off = node->key + le16_to_cpu(entry->k);
	} else {
		/* These node types have variable length keys and data */
		struct apfs_kvloc *entry;

		entry = (struct apfs_kvloc *)raw->btn_data + index;
		len = le16_to_cpu(entry->k.len);
		/* Translate offset in key area to offset in block */
		*off = node->key + le16_to_cpu(entry->k.off);
	}

	if (*off + len > sb->s_blocksize) {
		/* Avoid out-of-bounds read if corrupted */
		return 0;
	}
	return len;
}

/**
 * apfs_node_locate_data - Locate the data of a node record
 * @node:	node to be searched
 * @index:	number of the entry to locate
 * @off:	on return will hold the offset in the block
 *
 * Returns the length of the data, or 0 in case of failure. The function checks
 * that this length fits within the block; callers must use the returned value
 * to make sure they never operate outside its bounds.
 */
static int apfs_node_locate_data(struct apfs_node *node, int index, int *off)
{
	struct super_block *sb = node->object.sb;
	struct apfs_btree_node_phys *raw;
	int len;

	if (index >= node->records)
		return 0;

	raw = (struct apfs_btree_node_phys *)node->object.bh->b_data;
	if (apfs_node_has_fixed_kv_size(node)) {
		/* These node types have fixed length keys and data */
		struct apfs_kvoff *entry;

		entry = (struct apfs_kvoff *)raw->btn_data + index;
		/* Node type decides length */
		len = apfs_node_is_leaf(node) ? 16 : 8;
		/*
		 * Data offsets are counted backwards from the end of the
		 * block, or from the beginning of the footer when it exists
		 */
		if (apfs_node_is_root(node)) /* has footer */
			*off = sb->s_blocksize - sizeof(struct apfs_btree_info)
					- le16_to_cpu(entry->v);
		else
			*off = sb->s_blocksize - le16_to_cpu(entry->v);
	} else {
		/* These node types have variable length keys and data */
		struct apfs_kvloc *entry;

		entry = (struct apfs_kvloc *)raw->btn_data + index;
		len = le16_to_cpu(entry->v.len);
		/*
		 * Data offsets are counted backwards from the end of the
		 * block, or from the beginning of the footer when it exists
		 */
		if (apfs_node_is_root(node)) /* has footer */
			*off = sb->s_blocksize - sizeof(struct apfs_btree_info)
					- le16_to_cpu(entry->v.off);
		else
			*off = sb->s_blocksize - le16_to_cpu(entry->v.off);
	}

	if (*off < 0 || *off + len > sb->s_blocksize) {
		/* Avoid out-of-bounds read if corrupted */
		return 0;
	}
	return len;
}

/**
 * apfs_key_from_query - Read the current key from a query structure
 * @query:	the query, with @query->key_off and @query->key_len already set
 * @key:	return parameter for the key
 *
 * Reads the key into @key and performs some basic sanity checks as a
 * protection against crafted filesystems.  Returns 0 on success or a
 * negative error code otherwise.
 */
static int apfs_key_from_query(struct apfs_query *query, struct apfs_key *key)
{
	struct super_block *sb = query->node->object.sb;
	char *raw = query->node->object.bh->b_data;
	void *raw_key = (void *)(raw + query->key_off);
	int err = 0;

	switch (query->flags & APFS_QUERY_TREE_MASK) {
	case APFS_QUERY_CAT:
		err = apfs_read_cat_key(raw_key, query->key_len, key);
		break;
	case APFS_QUERY_OMAP:
		err = apfs_read_omap_key(raw_key, query->key_len, key);
		break;
	default:
		/* Not implemented yet */
		err = -EINVAL;
		break;
	}
	if (err) {
		apfs_alert(sb, "bad node key in block 0x%llx",
			   query->node->object.block_nr);
	}

	/* A multiple query must ignore some of these fields */
	if (query->flags & APFS_QUERY_ANY_NAME)
		key->name = NULL;
	if (query->flags & APFS_QUERY_ANY_NUMBER)
		key->number = 0;

	return err;
}

/**
 * apfs_node_next - Find the next matching record in the current node
 * @sb:		filesystem superblock
 * @query:	multiple query in execution
 *
 * Returns 0 on success, -EAGAIN if the next record is in another node,
 * -ENODATA if no more matching records exist, or another negative error
 * code in case of failure.
 */
static int apfs_node_next(struct super_block *sb, struct apfs_query *query)
{
	struct apfs_node *node = query->node;
	struct apfs_key curr_key;
	int cmp, err;

	if (query->flags & APFS_QUERY_DONE)
		/* Nothing left to search; the query failed */
		return -ENODATA;

	if (!query->index) /* The next record may be in another node */
		return -EAGAIN;
	--query->index;

	query->key_len = apfs_node_locate_key(node, query->index,
					      &query->key_off);
	err = apfs_key_from_query(query, &curr_key);
	if (err)
		return err;

	cmp = apfs_keycmp(sb, &curr_key, query->key);

	if (cmp > 0) /* Records are out of order */
		return -EFSCORRUPTED;

	if (cmp != 0 && apfs_node_is_leaf(node) &&
	    query->flags & APFS_QUERY_EXACT)
		return -ENODATA;

	query->len = apfs_node_locate_data(node, query->index, &query->off);
	if (query->len == 0)
		return -EFSCORRUPTED;

	if (cmp != 0) {
		/*
		 * This is the last entry that can be relevant in this node.
		 * Keep searching the children, but don't return to this level.
		 */
		query->flags |= APFS_QUERY_DONE;
	}

	return 0;
}

/**
 * apfs_node_query - Execute a query on a single node
 * @sb:		filesystem superblock
 * @query:	the query to execute
 *
 * The search will start at index @query->index, looking for the key that comes
 * right before @query->key, according to the order given by apfs_keycmp().
 *
 * The @query->index will be updated to the last index checked. This is
 * important when searching for multiple entries, since the query may need
 * to remember where it was on this level. If we are done with this node, the
 * query will be flagged as APFS_QUERY_DONE, and the search will end in failure
 * as soon as we return to this level. The function may also return -EAGAIN,
 * to signal that the search should go on in a different branch.
 *
 * On success returns 0; the offset of the data within the block will be saved
 * in @query->off, and its length in @query->len. The function checks that this
 * length fits within the block; callers must use the returned value to make
 * sure they never operate outside its bounds.
 *
 * -ENODATA will be returned if no appropriate entry was found, -EFSCORRUPTED
 * in case of corruption.
 */
int apfs_node_query(struct super_block *sb, struct apfs_query *query)
{
	struct apfs_node *node = query->node;
	int left, right;
	int cmp;
	int err;

	if (query->flags & APFS_QUERY_NEXT)
		return apfs_node_next(sb, query);

	/* Search by bisection */
	cmp = 1;
	left = 0;
	do {
		struct apfs_key curr_key;
		if (cmp > 0) {
			right = query->index - 1;
			if (right < left)
				return -ENODATA;
			query->index = (left + right) / 2;
		} else {
			left = query->index;
			query->index = DIV_ROUND_UP(left + right, 2);
		}

		query->key_len = apfs_node_locate_key(node, query->index,
						      &query->key_off);
		err = apfs_key_from_query(query, &curr_key);
		if (err)
			return err;

		cmp = apfs_keycmp(sb, &curr_key, query->key);
		if (cmp == 0 && !(query->flags & APFS_QUERY_MULTIPLE))
			break;
	} while (left != right);

	if (cmp > 0)
		return -ENODATA;

	if (cmp != 0 && apfs_node_is_leaf(query->node) &&
	    query->flags & APFS_QUERY_EXACT)
		return -ENODATA;

	if (query->flags & APFS_QUERY_MULTIPLE) {
		if (cmp != 0) /* Last relevant entry in level */
			query->flags |= APFS_QUERY_DONE;
		query->flags |= APFS_QUERY_NEXT;
	}

	query->len = apfs_node_locate_data(node, query->index, &query->off);
	if (query->len == 0)
		return -EFSCORRUPTED;
	return 0;
}

/**
 * apfs_bno_from_query - Read the block number found by a successful omap query
 * @query:	the query that found the record
 * @bno:	Return parameter.  The block number found.
 *
 * Reads the block number in the omap record into @bno and performs a basic
 * sanity check as a protection against crafted filesystems.  Returns 0 on
 * success or -EFSCORRUPTED otherwise.
 */
int apfs_bno_from_query(struct apfs_query *query, u64 *bno)
{
	struct apfs_omap_val *omap_val;
	char *raw = query->node->object.bh->b_data;

	if (query->len != sizeof(*omap_val))
		return -EFSCORRUPTED;

	omap_val = (struct apfs_omap_val *)(raw + query->off);
	*bno = le64_to_cpu(omap_val->ov_paddr);
	return 0;
}
