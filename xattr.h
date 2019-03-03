/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/xattr.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_XATTR_H
#define _APFS_XATTR_H

#include <linux/types.h>
#include "inode.h"

/* Extended attributes constants */
#define APFS_XATTR_MAX_EMBEDDED_SIZE	3804

/* Extended attributes names */
#define APFS_XATTR_NAME_SYMLINK		"com.apple.fs.symlink"
#define APFS_XATTR_NAME_COMPRESSED	"com.apple.decmpfs"

/* Extended attributes flags */
enum {
	APFS_XATTR_DATA_STREAM		= 0x00000001,
	APFS_XATTR_DATA_EMBEDDED	= 0x00000002,
	APFS_XATTR_FILE_SYSTEM_OWNED	= 0x00000004,
	APFS_XATTR_RESERVED_8		= 0x00000008,
};

/*
 * Structure of the value of an extended attributes record
 */
struct apfs_xattr_val {
	__le16 flags;
	__le16 xdata_len;
	u8 xdata[0];
} __packed;

/*
 * Structure used to store the data of an extended attributes record
 */
struct apfs_xattr_dstream {
	__le64 xattr_obj_id;
	struct apfs_dstream dstream;
} __packed;

/*
 * Xattr record data in memory
 */
struct apfs_xattr {
	u8 *name;
	u8 *xdata;
	int name_len;
	int xdata_len;
	bool has_dstream;
};

extern int apfs_xattr_get(struct inode *inode, const char *name, void *buffer,
			  size_t size);
extern ssize_t apfs_listxattr(struct dentry *dentry, char *buffer, size_t size);

extern const struct xattr_handler *apfs_xattr_handlers[];

#endif	/* _APFS_XATTR_H */
