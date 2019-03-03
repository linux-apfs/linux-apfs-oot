// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/dir.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include "apfs.h"
#include "btree.h"
#include "dir.h"
#include "key.h"
#include "message.h"
#include "node.h"
#include "super.h"

/**
 * apfs_drec_from_query - Read the directory record found by a successful query
 * @query:	the query that found the record
 * @drec:	Return parameter.  The directory record found.
 *
 * Reads the directory record into @drec and performs some basic sanity checks
 * as a protection against crafted filesystems.  Returns 0 on success or
 * -EFSCORRUPTED otherwise.
 *
 * The caller must not free @query while @drec is in use, because @drec->name
 * points to data on disk.
 */
int apfs_drec_from_query(struct apfs_query *query, struct apfs_drec *drec)
{
	char *raw = query->node->object.bh->b_data;
	struct apfs_drec_hashed_key *de_key;
	struct apfs_drec_val *de;
	int namelen = query->key_len - sizeof(*de_key);

	if (namelen < 1)
		return -EFSCORRUPTED;
	if (query->len < sizeof(*de))
		return -EFSCORRUPTED;

	de = (struct apfs_drec_val *)(raw + query->off);
	de_key = (struct apfs_drec_hashed_key *)(raw + query->key_off);

	if (namelen != (le32_to_cpu(de_key->name_len_and_hash) &
			APFS_DREC_LEN_MASK))
		return -EFSCORRUPTED;

	/* Filename must be NULL-terminated */
	if (de_key->name[namelen - 1] != 0)
		return -EFSCORRUPTED;

	drec->name = de_key->name;
	drec->name_len = namelen - 1; /* Don't count the NULL termination */
	drec->ino = le64_to_cpu(de->file_id);

	drec->type = le16_to_cpu(de->flags) & APFS_DREC_TYPE_MASK;
	if (drec->type != DT_FIFO && drec->type & 1) /* Invalid file type */
		drec->type = DT_UNKNOWN;
	return 0;
}

/**
 * apfs_inode_by_name - Find the cnid for a given filename
 * @dir:	parent directory
 * @child:	filename
 * @ino:	on return, the inode number found
 *
 * Returns 0 and the inode number (which is the cnid of the file
 * record); otherwise, return the appropriate error code.
 */
int apfs_inode_by_name(struct inode *dir, const struct qstr *child, u64 *ino)
{
	struct super_block *sb = dir->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key key;
	struct apfs_query *query;
	struct apfs_drec drec;
	u64 cnid = dir->i_ino;
	int err;

	apfs_init_drec_hashed_key(sb, cnid, child->name, &key);

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return -ENOMEM;
	query->key = &key;

	/*
	 * Distinct filenames in the same directory may (rarely) share the same
	 * hash.  The query code cannot handle that because their order in the
	 * b-tree would	depend on their unnormalized original names.  Just get
	 * all the candidates and check them one by one.
	 */
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_ANY_NAME | APFS_QUERY_EXACT;
	do {
		err = apfs_btree_query(sb, &query);
		if (err)
			goto out;
		err = apfs_drec_from_query(query, &drec);
		if (err)
			goto out;
	} while (unlikely(apfs_filename_cmp(sb, child->name, drec.name)));

	*ino = drec.ino;
out:
	apfs_free_query(sb, query);
	return err;
}

static int apfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key key;
	struct apfs_query *query;
	u64 cnid = inode->i_ino;
	loff_t pos;
	int err = 0;

	if (ctx->pos == 0) {
		if (!dir_emit_dot(file, ctx))
			return 0;
		ctx->pos++;
	}
	if (ctx->pos == 1) {
		if (!dir_emit_dotdot(file, ctx))
			return 0;
		ctx->pos++;
	}

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return -ENOMEM;

	/* We want all the children for the cnid, regardless of the name */
	apfs_init_drec_hashed_key(sb, cnid, NULL /* name */, &key);
	query->key = &key;
	query->flags = APFS_QUERY_CAT | APFS_QUERY_MULTIPLE | APFS_QUERY_EXACT;

	pos = ctx->pos - 2;
	while (1) {
		struct apfs_drec drec;
		/*
		 * We query for the matching records, one by one. After we
		 * pass ctx->pos we begin to emit them.
		 *
		 * TODO: Faster approach for large directories?
		 */

		err = apfs_btree_query(sb, &query);
		if (err == -ENODATA) { /* Got all the records */
			err = 0;
			break;
		}
		if (err)
			break;

		err = apfs_drec_from_query(query, &drec);
		if (err) {
			apfs_alert(sb, "bad dentry record in directory 0x%llx",
				   cnid);
			break;
		}

		err = 0;
		if (pos <= 0) {
			if (!dir_emit(ctx, drec.name, drec.name_len,
				      drec.ino, drec.type))
				break;
			ctx->pos++;
		}
		pos--;
	}

	if (pos < 0)
		ctx->pos -= pos;
	apfs_free_query(sb, query);
	return err;
}

const struct file_operations apfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= apfs_readdir,
};
