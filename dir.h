/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/dir.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_DIR_H
#define _APFS_DIR_H

#include <linux/types.h>

struct inode;
struct qstr;
struct apfs_query;

/*
 * Structure of the value of a directory entry. This is the data in
 * the catalog nodes for record type APFS_TYPE_DIR_REC.
 */
struct apfs_drec_val {
	__le64 file_id;
	__le64 date_added;
	__le16 flags;
	u8 xfields[];
} __packed;

/*
 * Directory entry record in memory
 */
struct apfs_drec {
	u8 *name;
	u64 ino;
	int name_len;
	unsigned int type;
};

extern int apfs_drec_from_query(struct apfs_query *query,
				struct apfs_drec *drec);
extern int apfs_inode_by_name(struct inode *dir, const struct qstr *child,
			      u64 *ino);

extern const struct file_operations apfs_dir_operations;

#endif	/* _APFS_DIR_H */
