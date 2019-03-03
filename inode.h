/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/inode.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_INODE_H
#define _APFS_INODE_H

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include "extents.h"

/* Inode numbers for special inodes */
#define APFS_INVALID_INO_NUM		0

#define APFS_ROOT_DIR_PARENT		1	/* Root directory parent */
#define APFS_ROOT_DIR_INO_NUM		2	/* Root directory */
#define APFS_PRIV_DIR_INO_NUM		3	/* Private directory */
#define APFS_SNAP_DIR_INO_NUM		6	/* Snapshots metadata */

/* Smallest inode number available for user content */
#define APFS_MIN_USER_INO_NUM		16

/*
 * Structure of an inode as stored as a B-tree value
 */
struct apfs_inode_val {
/*00*/	__le64 parent_id;
	__le64 private_id;
/*10*/	__le64 create_time;
	__le64 mod_time;
	__le64 change_time;
	__le64 access_time;
/*30*/	__le64 internal_flags;
	union {
		__le32 nchildren;
		__le32 nlink;
	};
	__le32 default_protection_class;
/*40*/	__le32 write_generation_counter;
	__le32 bsd_flags;
	__le32 owner;
	__le32 group;
/*50*/	__le16 mode;
	__le16 pad1;
	__le64 pad2;
/*5C*/	u8 xfields[];
} __packed;

/* Extended field types */
#define APFS_DREC_EXT_TYPE_SIBLING_ID 1

#define APFS_INO_EXT_TYPE_SNAP_XID 1
#define APFS_INO_EXT_TYPE_DELTA_TREE_OID 2
#define APFS_INO_EXT_TYPE_DOCUMENT_ID 3
#define APFS_INO_EXT_TYPE_NAME 4
#define APFS_INO_EXT_TYPE_PREV_FSIZE 5
#define APFS_INO_EXT_TYPE_RESERVED_6 6
#define APFS_INO_EXT_TYPE_FINDER_INFO 7
#define APFS_INO_EXT_TYPE_DSTREAM 8
#define APFS_INO_EXT_TYPE_RESERVED_9 9
#define APFS_INO_EXT_TYPE_DIR_STATS_KEY 10
#define APFS_INO_EXT_TYPE_FS_UUID 11
#define APFS_INO_EXT_TYPE_RESERVED_12 12
#define APFS_INO_EXT_TYPE_SPARSE_BYTES 13
#define APFS_INO_EXT_TYPE_RDEV 14

/*
 * Structure used to store the number and size of extended fields of an inode
 */
struct apfs_xf_blob {
	__le16 xf_num_exts;
	__le16 xf_used_data;
	u8 xf_data[];
} __packed;

/*
 * Structure used to store an inode's extended field
 */
struct apfs_x_field {
	u8 x_type;
	u8 x_flags;
	__le16 x_size;
} __packed;

/*
 * Structure of a data stream record
 */
struct apfs_dstream_id_val {
	__le32 refcnt;
} __packed;

/*
 * Structure used to store information about a data stream
 */
struct apfs_dstream {
	__le64 size;
	__le64 alloced_size;
	__le64 default_crypto_id;
	__le64 total_bytes_written;
	__le64 total_bytes_read;
} __packed;

/*
 * APFS inode data in memory
 */
struct apfs_inode_info {
	u64			i_extent_id;	 /* ID of the extent records */
	struct apfs_file_extent	i_cached_extent; /* Latest extent record */
	spinlock_t		i_extent_lock;	 /* Protects i_cached_extent */
	struct timespec64	i_crtime;	 /* Time of creation */

#if BITS_PER_LONG == 32
	/* This is the actual inode number; vfs_inode.i_ino could overflow */
	u64			i_ino;
#endif
	struct inode vfs_inode;
};

static inline struct apfs_inode_info *APFS_I(struct inode *inode)
{
	return container_of(inode, struct apfs_inode_info, vfs_inode);
}

extern struct inode *apfs_iget(struct super_block *sb, u64 cnid);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0) /* No statx yet... */
extern int apfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			struct kstat *stat);
#else
extern int apfs_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int query_flags);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0) */

#endif	/* _APFS_INODE_H */
