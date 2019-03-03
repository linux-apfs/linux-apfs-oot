/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/message.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_MESSAGE_H
#define _APFS_MESSAGE_H

struct super_block;

extern __printf(3, 4)
void apfs_msg(struct super_block *sb, const char *prefix, const char *fmt, ...);

#define apfs_emerg(sb, fmt, ...) apfs_msg(sb, KERN_EMERG, fmt, ##__VA_ARGS__)
#define apfs_alert(sb, fmt, ...) apfs_msg(sb, KERN_ALERT, fmt, ##__VA_ARGS__)
#define apfs_crit(sb, fmt, ...) apfs_msg(sb, KERN_CRIT, fmt, ##__VA_ARGS__)
#define apfs_err(sb, fmt, ...) apfs_msg(sb, KERN_ERR, fmt, ##__VA_ARGS__)
#define apfs_warn(sb, fmt, ...) apfs_msg(sb, KERN_WARNING, fmt, ##__VA_ARGS__)
#define apfs_notice(sb, fmt, ...) apfs_msg(sb, KERN_NOTICE, fmt, ##__VA_ARGS__)
#define apfs_info(sb, fmt, ...) apfs_msg(sb, KERN_INFO, fmt, ##__VA_ARGS__)

#ifdef CONFIG_APFS_DEBUG
#define apfs_debug(sb, fmt, ...) apfs_msg(sb, KERN_DEBUG, fmt, ##__VA_ARGS__)
#else
#define apfs_debug(sb, fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#endif

#endif	/* _APFS_MESSAGE_H */
