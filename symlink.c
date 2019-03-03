// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/symlink.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include "apfs.h"
#include "message.h"
#include "xattr.h"

/**
 * apfs_get_link - Follow a symbolic link
 * @dentry:	dentry for the link
 * @inode:	inode for the link
 * @done:	delayed call to free the returned buffer after use
 *
 * Returns a pointer to a buffer containing the target path, or an appropriate
 * error pointer in case of failure.
 */
static const char *apfs_get_link(struct dentry *dentry, struct inode *inode,
				 struct delayed_call *done)
{
	struct super_block *sb = inode->i_sb;
	char *target, *err;
	int size;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	size = apfs_xattr_get(inode, APFS_XATTR_NAME_SYMLINK,
			      NULL /* buffer */, 0 /* size */);
	if (size < 0) /* TODO: return a better error code */
		return ERR_PTR(size);

	target = kmalloc(size, GFP_KERNEL);
	if (!target)
		return ERR_PTR(-ENOMEM);

	size = apfs_xattr_get(inode, APFS_XATTR_NAME_SYMLINK, target, size);
	if (size < 0) {
		err = ERR_PTR(size);
		goto fail;
	}
	if (size == 0 || *(target + size - 1) != 0) {
		/* Target path must be NULL-terminated */
		apfs_alert(sb, "bad link target in inode 0x%llx",
			   (unsigned long long) inode->i_ino);
		err = ERR_PTR(-EFSCORRUPTED);
		goto fail;
	}

	set_delayed_call(done, kfree_link, target);
	return target;

fail:
	kfree(target);
	return err;
}

const struct inode_operations apfs_symlink_inode_operations = {
	.get_link	= apfs_get_link,
	.getattr	= apfs_getattr,
	.listxattr	= apfs_listxattr,
};
