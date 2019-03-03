// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/file.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include "apfs.h"
#include "inode.h"
#include "xattr.h"

const struct file_operations apfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_readonly_mmap,
	.open		= generic_file_open,
};

const struct inode_operations apfs_file_inode_operations = {
	.getattr	= apfs_getattr,
	.listxattr	= apfs_listxattr,
};
