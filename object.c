// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/object.c
 *
 * Checksum routines for an APFS object
 */

#include <linux/fs.h>
#include "object.h"

/*
 * Note that this is not a generic implementation of fletcher64, as it assumes
 * a message length that doesn't overflow sum1 and sum2.  This constraint is ok
 * for apfs, though, since the block size is limited to 2^16.  For a more
 * generic optimized implementation, see Nakassis (1988).
 */
static u64 apfs_fletcher64(void *addr, size_t len)
{
	__le32 *buff = addr;
	u64 sum1 = 0;
	u64 sum2 = 0;
	u64 c1, c2;
	int i;

	for (i = 0; i < len/sizeof(u32); i++) {
		sum1 += le32_to_cpu(buff[i]);
		sum2 += sum1;
	}

	c1 = sum1 + sum2;
	c1 = 0xFFFFFFFF - do_div(c1, 0xFFFFFFFF);
	c2 = sum1 + c1;
	c2 = 0xFFFFFFFF - do_div(c2, 0xFFFFFFFF);

	return (c2 << 32) | c1;
}

int apfs_obj_verify_csum(struct super_block *sb, struct apfs_obj_phys *obj)
{
	return  (le64_to_cpu(obj->o_cksum) ==
		 apfs_fletcher64((char *) obj + APFS_MAX_CKSUM_SIZE,
				 sb->s_blocksize - APFS_MAX_CKSUM_SIZE));
}
