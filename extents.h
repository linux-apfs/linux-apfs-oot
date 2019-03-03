/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/extents.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _EXTENTS_H
#define _EXTENTS_H

#include <linux/types.h>

struct inode;
struct buffer_head;
struct apfs_query;

/* File extent records */
#define APFS_FILE_EXTENT_LEN_MASK	0x00ffffffffffffffULL
#define APFS_FILE_EXTENT_FLAG_MASK	0xff00000000000000ULL
#define APFS_FILE_EXTENT_FLAG_SHIFT	56

/*
 * Structure of a file extent record
 */
struct apfs_file_extent_val {
	__le64 len_and_flags;
	__le64 phys_block_num;
	__le64 crypto_id;
} __packed;

/*
 * Extent record data in memory
 */
struct apfs_file_extent {
	u64 logical_addr;
	u64 phys_block_num;
	u64 len;
};

extern int apfs_extent_from_query(struct apfs_query *query,
				  struct apfs_file_extent *extent);
extern int apfs_get_block(struct inode *inode, sector_t iblock,
			  struct buffer_head *bh_result, int create);

#endif	/* _EXTENTS_H */
