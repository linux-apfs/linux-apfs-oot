// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/inode.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <asm/div64.h>
#include "apfs.h"
#include "btree.h"
#include "dir.h"
#include "extents.h"
#include "inode.h"
#include "key.h"
#include "message.h"
#include "node.h"
#include "super.h"
#include "xattr.h"

static int apfs_readpage(struct file *file, struct page *page)
{
        return mpage_readpage(page, apfs_get_block);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
static void apfs_readahead(struct readahead_control *rac)
{
        mpage_readahead(rac, apfs_get_block);
}
#else
static int apfs_readpages(struct file *file, struct address_space *mapping,
                          struct list_head *pages, unsigned int nr_pages)
{
        return mpage_readpages(mapping, pages, nr_pages, apfs_get_block);
}
#endif
static sector_t apfs_bmap(struct address_space *mapping, sector_t block)
{
        return generic_block_bmap(mapping, block, apfs_get_block);
}

static const struct address_space_operations apfs_aops = {
        .readpage       = apfs_readpage,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
        .readahead      = apfs_readahead,
#else
        .readpages      = apfs_readpages,
#endif
        .bmap           = apfs_bmap,
};

/**
 * apfs_inode_from_query - Read the inode found by a successful query
 * @query:      the query that found the record
 * @inode:      vfs inode to be filled with the read data
 *
 * Reads the inode record into @inode and performs some basic sanity checks,
 * mostly as a protection against crafted filesystems.  Returns 0 on success
 * or a negative error code otherwise.
 */
static int apfs_inode_from_query(struct apfs_query *query, struct inode *inode)
{
        struct apfs_inode_info *ai = APFS_I(inode);
        struct apfs_inode_val *inode_val;
        struct apfs_dstream *dstream = NULL;
        struct apfs_xf_blob *xblob;
        struct apfs_x_field *xfield;
        char *raw = query->node->object.bh->b_data;
        int rest, i;
        u64 secs;

        if (query->len < sizeof(*inode_val))
                return -EFSCORRUPTED;

        inode_val = (struct apfs_inode_val *)(raw + query->off);

        ai->i_extent_id = le64_to_cpu(inode_val->private_id);
        inode->i_mode = le16_to_cpu(inode_val->mode);
        i_uid_write(inode, (uid_t)le32_to_cpu(inode_val->owner));
        i_gid_write(inode, (gid_t)le32_to_cpu(inode_val->group));

        if (S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
                /*
                 * It seems that hard links are only allowed for regular files,
                 * and perhaps for symlinks.
                 *
                 * Directory inodes don't store their link count, so to provide
                 * it we would have to actually count the subdirectories. The
                 * HFS/HFS+ modules just leave it at 1, and so do we, for now.
                 */
                set_nlink(inode, le32_to_cpu(inode_val->nlink));
        }

        /* APFS stores the time as unsigned nanoseconds since the epoch */
        secs = le64_to_cpu(inode_val->access_time);
        inode->i_atime.tv_nsec = do_div(secs, NSEC_PER_SEC);
        inode->i_atime.tv_sec = secs;
        secs = le64_to_cpu(inode_val->change_time);
        inode->i_ctime.tv_nsec = do_div(secs, NSEC_PER_SEC);
        inode->i_ctime.tv_sec = secs;
        secs = le64_to_cpu(inode_val->mod_time);
        inode->i_mtime.tv_nsec = do_div(secs, NSEC_PER_SEC);
        inode->i_mtime.tv_sec = secs;
        secs = le64_to_cpu(inode_val->create_time);
        ai->i_crtime.tv_nsec = do_div(secs, NSEC_PER_SEC);
        ai->i_crtime.tv_sec = secs;

        xblob = (struct apfs_xf_blob *) inode_val->xfields;
        xfield = (struct apfs_x_field *) xblob->xf_data;
        rest = query->len - (sizeof(*inode_val) + sizeof(*xblob));
        rest -= le16_to_cpu(xblob->xf_num_exts) * sizeof(xfield[0]);
        if (rest < 0)
                return -EFSCORRUPTED;
        for (i = 0; i < le16_to_cpu(xblob->xf_num_exts); ++i) {
                int attrlen;

                /* Attribute length is padded to a multiple of 8 */
                attrlen = round_up(le16_to_cpu(xfield[i].x_size), 8);
                if (attrlen > rest)
                        break;
                if (xfield[i].x_type == APFS_INO_EXT_TYPE_DSTREAM) {
                        /* The only optional attr we care about, for now */
                        dstream = (struct apfs_dstream *)
                                        ((char *)inode_val + query->len - rest);
                        break;
                }
                rest -= attrlen;
        }

        if (dstream) {
                inode->i_size = le64_to_cpu(dstream->size);
                inode->i_blocks = le64_to_cpu(dstream->alloced_size) >> 9;
        } else {
                /*
                 * This inode is "empty", but it may actually hold compressed
                 * data in the named attribute com.apple.decmpfs, and sometimes
                 * in com.apple.ResourceFork
                 */
                inode->i_size = inode->i_blocks = 0;
        }

        return 0;
}

/**
 * apfs_inode_lookup - Lookup an inode record in the b-tree and read its data
 * @inode:      vfs inode to lookup and fill
 *
 * Queries the b-tree for the @inode->i_ino inode record and reads its data to
 * @inode.  Returns 0 on success or a negative error code otherwise.
 */
static int apfs_inode_lookup(struct inode *inode)
{
        struct super_block *sb = inode->i_sb;
        struct apfs_sb_info *sbi = APFS_SB(sb);
        struct apfs_key key;
        struct apfs_query *query;
        u64 cnid = inode->i_ino;
        int ret;

        apfs_init_inode_key(cnid, &key);

        query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
        if (!query)
                return -ENOMEM;
        query->key = &key;
        query->flags |= APFS_QUERY_CAT | APFS_QUERY_EXACT;

        ret = apfs_btree_query(sb, &query);
        if (ret)
                goto done;

        ret = apfs_inode_from_query(query, inode);
        if (ret)
                apfs_alert(sb, "bad inode record for inode 0x%llx", cnid);

done:
        apfs_free_query(sb, query);
        return ret;
}

#if BITS_PER_LONG == 64
#define apfs_iget_locked iget_locked
#else /* 64-bit inode numbers may not fit in the vfs inode */

/**
 * apfs_test_inode - Check if the inode matches a 64-bit inode number
 * @inode:      inode to test
 * @cnid:       pointer to the inode number
 */
static int apfs_test_inode(struct inode *inode, void *cnid)
{
        struct apfs_inode_info *ai = APFS_I(inode);
        u64 *ino = cnid;

        return ai->i_ino == *ino;
}

/**
 * apfs_set_inode - Set a 64-bit inode number on the given inode
 * @inode:      inode to set
 * @cnid:       pointer to the inode number
 */
static int apfs_set_inode(struct inode *inode, void *cnid)
{
        struct apfs_inode_info *ai = APFS_I(inode);
        u64 *ino = cnid;

        ai->i_ino = *ino;
        inode->i_ino = *ino; /* Just discard the higher bits here... */
        return 0;
}

/**
 * apfs_iget_locked - Wrapper for iget5_locked()
 * @sb:         filesystem superblock
 * @cnid:       64-bit inode number
 *
 * Works the same as iget_locked(), but supports 64-bit inode numbers.
 */
static struct inode *apfs_iget_locked(struct super_block *sb, u64 cnid)
{
        return iget5_locked(sb, cnid, apfs_test_inode, apfs_set_inode, &cnid);
}

#endif /* BITS_PER_LONG == 64 */

/**
 * apfs_iget - Populate inode structures with metadata from disk
 * @sb:         filesystem superblock
 * @cnid:       inode number
 *
 * Populates the vfs inode and the corresponding apfs_inode_info structure.
 * Returns a pointer to the vfs inode in case of success, or an appropriate
 * error pointer otherwise.
 */
struct inode *apfs_iget(struct super_block *sb, u64 cnid)
{
        struct apfs_sb_info *sbi = APFS_SB(sb);
        struct inode *inode;
        int err;

        inode = apfs_iget_locked(sb, cnid);
        if (!inode)
                return ERR_PTR(-ENOMEM);
        if (!(inode->i_state & I_NEW))
                return inode;

        err = apfs_inode_lookup(inode);
        if (err) {
                iget_failed(inode);
                return ERR_PTR(err);
        }

        /* Allow the user to override the ownership */
        if (sbi->s_flags & APFS_UID_OVERRIDE)
                inode->i_uid = sbi->s_uid;
        if (sbi->s_flags & APFS_GID_OVERRIDE)
                inode->i_gid = sbi->s_gid;

        /* A lot of operations still missing, of course */
        if (S_ISREG(inode->i_mode)) {
                inode->i_op = &apfs_file_inode_operations;
                inode->i_fop = &apfs_file_operations;
                inode->i_mapping->a_ops = &apfs_aops;
        } else if (S_ISDIR(inode->i_mode)) {
                inode->i_op = &apfs_dir_inode_operations;
                inode->i_fop = &apfs_dir_operations;
        } else if (S_ISLNK(inode->i_mode)) {
                inode->i_op = &apfs_symlink_inode_operations;
        } else {
                inode->i_op = &apfs_special_inode_operations;
        }

        /* Inode flags are not important for now, leave them at 0 */
        unlock_new_inode(inode);
        return inode;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0) /* No statx yet... */

int apfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
                 struct kstat *stat)
{
        struct inode *inode = d_inode(dentry);

        generic_fillattr(inode, stat);
#if BITS_PER_LONG == 32
        stat->ino = ai->i_ino;
#endif /* BITS_PER_LONG == 32 */
        return 0;
}

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0) */

int apfs_getattr(const struct path *path, struct kstat *stat,
                 u32 request_mask, unsigned int query_flags)
{
        struct inode *inode = d_inode(path->dentry);
        struct apfs_inode_info *ai = APFS_I(inode);

        stat->result_mask |= STATX_BTIME;
        stat->btime = ai->i_crtime;

        if (apfs_xattr_get(inode, APFS_XATTR_NAME_COMPRESSED, NULL, 0) >= 0)
                stat->attributes |= STATX_ATTR_COMPRESSED;

        stat->attributes_mask |= STATX_ATTR_COMPRESSED;

        generic_fillattr(inode, stat);
#if BITS_PER_LONG == 32
        stat->ino = ai->i_ino;
#endif /* BITS_PER_LONG == 32 */
        return 0;
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0) *
