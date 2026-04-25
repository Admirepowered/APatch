/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KPU_SUPERCALL_H_
#define _KPU_SUPERCALL_H_

#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <alloca.h>

#include "uapi/scdefs.h"

/**
 * @brief Get a supercall fd by opening /dev/kp.
 * The kernel hook on openat installs an anonymous inode for the trusted manager.
 *
 * @return int: fd on success, negative on failure
 */
static inline int sc_get_fd(void)
{
    return open(KP_DEVICE_PATH, O_RDWR);
}

/**
 * @brief Is KernelPatch installed?
 *
 * @param fd: supercall fd
 * @return true
 * @return false
 */
static inline bool sc_ready(int fd)
{
    return ioctl(fd, SUPERCALL_HELLO, 0) == SUPERCALL_HELLO_MAGIC;
}

/**
 * @brief Print messages by printk in the kernel
 *
 * @param fd: supercall fd
 * @param msg
 * @return long
 */
static inline long sc_klog(int fd, const char *msg)
{
    if (!msg || strlen(msg) <= 0) return -EINVAL;
    return ioctl(fd, SUPERCALL_KLOG, msg);
}

/**
 * @brief KernelPatch version number
 *
 * @param fd: supercall fd
 * @return uint32_t
 */
static inline uint32_t sc_kp_ver(int fd)
{
    return (uint32_t)ioctl(fd, SUPERCALL_KERNELPATCH_VER, 0);
}

/**
 * @brief Kernel version number
 *
 * @param fd: supercall fd
 * @return uint32_t
 */
static inline uint32_t sc_k_ver(int fd)
{
    return (uint32_t)ioctl(fd, SUPERCALL_KERNEL_VER, 0);
}

/**
 * @brief KernelPatch build time
 *
 * @param fd: supercall fd
 * @param out_buildtime
 * @param outlen
 * @return long
 */
static inline long sc_kp_buildtime(int fd, char *out_buildtime, int outlen)
{
    if (!out_buildtime || outlen <= 0) return -EINVAL;
    return ioctl(fd, SUPERCALL_BUILD_TIME, out_buildtime);
}

/**
 * @brief Substitute user of current thread
 *
 * @param fd: supercall fd
 * @param profile: if scontext is invalid or illegal, all selinux permission checks will bypass via hook
 * @see struct su_profile
 * @return long : 0 if succeed
 */
static inline long sc_su(int fd, struct su_profile *profile)
{
    if (!profile) return -EINVAL;
    if (strlen(profile->scontext) >= SUPERCALL_SCONTEXT_LEN) return -EINVAL;
    return ioctl(fd, SUPERCALL_SU, profile);
}

/**
 * @brief Substitute user of tid specfied thread
 *
 * @param fd: supercall fd
 * @param tid : target thread id
 * @param profile: if scontext is invalid or illegal, all selinux permission checks will bypass via hook
 * @see struct su_profile
 * @return long : 0 if succeed
 */
static inline long sc_su_task(int fd, pid_t tid, struct su_profile *profile)
{
    if (!profile) return -EINVAL;
    struct {
        pid_t pid;
        struct su_profile profile;
    } args;
    args.pid = tid;
    memcpy(&args.profile, profile, sizeof(struct su_profile));
    return ioctl(fd, SUPERCALL_SU_TASK, &args);
}

/**
 * @brief Grant su permission
 *
 * @param fd: supercall fd
 * @param profile : if scontext is invalid or illegal, all selinux permission checks will bypass via hook
 * @return long : 0 if succeed
 */
static inline long sc_su_grant_uid(int fd, struct su_profile *profile)
{
    if (!profile) return -EINVAL;
    return ioctl(fd, SUPERCALL_SU_GRANT_UID, profile);
}

/**
 * @brief Revoke su permission
 *
 * @param fd: supercall fd
 * @param uid
 * @return long 0 if succeed
 */
static inline long sc_su_revoke_uid(int fd, uid_t uid)
{
    return ioctl(fd, SUPERCALL_SU_REVOKE_UID, &uid);
}

/**
 * @brief Get numbers of su allowed uids
 *
 * @param fd: supercall fd
 * @return long
 */
static inline long sc_su_uid_nums(int fd)
{
    return ioctl(fd, SUPERCALL_SU_NUMS, 0);
}

/**
 * @brief List all su allowed uids
 *
 * @param fd: supercall fd
 * @param buf
 * @param num
 * @return long : The numbers of uids if succeed, negative value if failed
 */
static inline long sc_su_allow_uids(int fd, uid_t *buf, int num)
{
    if (!buf || num <= 0) return -EINVAL;
    struct {
        int num;
        uid_t *uids;
    } args = { num, buf };
    return ioctl(fd, SUPERCALL_SU_LIST, &args);
}

/**
 * @brief Get su profile of specified uid
 *
 * @param fd: supercall fd
 * @param uid
 * @param out_profile
 * @return long : 0 if succeed
 */
static inline long sc_su_uid_profile(int fd, uid_t uid, struct su_profile *out_profile)
{
    if (!out_profile) return -EINVAL;
    struct {
        uid_t uid;
        struct su_profile profile;
    } args;
    args.uid = uid;
    long ret = ioctl(fd, SUPERCALL_SU_PROFILE, &args);
    if (ret == 0) memcpy(out_profile, &args.profile, sizeof(struct su_profile));
    return ret;
}

/**
 * @brief Get full path of current 'su' command
 *
 * @param fd: supercall fd
 * @param out_path
 * @param path_len
 * @return long : The length of result string if succeed, negative if failed
 */
static inline long sc_su_get_path(int fd, char *out_path, int path_len)
{
    if (!out_path || path_len <= 0) return -EINVAL;
    struct {
        int len;
        char buf[0];
    } *args = reinterpret_cast<decltype(args)>(out_path);
    struct { int len; } get_path_args = { path_len };
    return ioctl(fd, SUPERCALL_SU_GET_PATH, &get_path_args);
}

/**
 * @brief Reset full path of 'su' command
 *
 * @param fd: supercall fd
 * @param path
 * @return long : 0 if succeed
 */
static inline long sc_su_reset_path(int fd, const char *path)
{
    if (!path || !path[0]) return -EINVAL;
    return ioctl(fd, SUPERCALL_SU_RESET_PATH, path);
}

/**
 * @brief Get current all-allowed selinux context
 *
 * @param fd: supercall fd
 * @param out_sctx
 * @param sctx_len
 * @return long
 */
static inline long sc_su_get_all_allow_sctx(int fd, char *out_sctx, int sctx_len)
{
    if (!out_sctx) return -EINVAL;
    struct { int len; } args = { sctx_len };
    return ioctl(fd, SUPERCALL_SU_GET_ALLOW_SCTX, &args);
}

/**
 * @brief Reset current all-allowed selinux context
 *
 * @param fd: supercall fd
 * @param sctx
 * @return long 0 if succeed
 */
static inline long sc_su_reset_all_allow_sctx(int fd, const char *sctx)
{
    if (!sctx) return -EINVAL;
    return ioctl(fd, SUPERCALL_SU_SET_ALLOW_SCTX, sctx);
}

/**
 * @brief Load module
 *
 * @param fd: supercall fd
 * @param path
 * @param args
 * @param reserved
 * @return long : 0 if succeed
 */
static inline long sc_kpm_load(int fd, const char *path, const char *args, void *reserved)
{
    if (!path || strlen(path) <= 0) return -EINVAL;
    struct {
        char path[1024];
        char args[1024];
    } kargs;
    memset(&kargs, 0, sizeof(kargs));
    strncpy(kargs.path, path, sizeof(kargs.path) - 1);
    if (args) strncpy(kargs.args, args, sizeof(kargs.args) - 1);
    return ioctl(fd, SUPERCALL_KPM_LOAD, &kargs);
}

/**
 * @brief Control module with arguments
 *
 * @param fd: supercall fd
 * @param name : module name
 * @param ctl_args : control argument
 * @param out_msg : output message buffer
 * @param outlen : buffer length of out_msg
 * @return long : 0 if succeed
 */
static inline long sc_kpm_control(int fd, const char *name, const char *ctl_args, char *out_msg, long outlen)
{
    if (!name || strlen(name) <= 0) return -EINVAL;
    if (!ctl_args || strlen(ctl_args) <= 0) return -EINVAL;
    struct kp_ioctl_kpm_control {
        char name[64];
        char args[1024];
        int outlen;
        char out_buf[0];
    };
    int total = sizeof(struct kp_ioctl_kpm_control) + outlen;
    struct kp_ioctl_kpm_control *buf = static_cast<struct kp_ioctl_kpm_control *>(alloca(total));
    if (!buf) return -ENOMEM;
    memset(buf, 0, total);
    strncpy(buf->name, name, sizeof(buf->name) - 1);
    strncpy(buf->args, ctl_args, sizeof(buf->args) - 1);
    buf->outlen = outlen;
    long ret = ioctl(fd, SUPERCALL_KPM_CONTROL, buf);
    if (ret >= 0 && out_msg) memcpy(out_msg, buf->out_buf, outlen);
    return ret;
}

/**
 * @brief Unload module
 *
 * @param fd: supercall fd
 * @param name : module name
 * @param reserved
 * @return long : 0 if succeed
 */
static inline long sc_kpm_unload(int fd, const char *name, void *reserved)
{
    if (!name || strlen(name) <= 0) return -EINVAL;
    struct {
        char name[64];
    } kargs;
    memset(&kargs, 0, sizeof(kargs));
    strncpy(kargs.name, name, sizeof(kargs.name) - 1);
    return ioctl(fd, SUPERCALL_KPM_UNLOAD, &kargs);
}

/**
 * @brief Current loaded module numbers
 *
 * @param fd: supercall fd
 * @return long
 */
static inline long sc_kpm_nums(int fd)
{
    return ioctl(fd, SUPERCALL_KPM_NUMS, 0);
}

/**
 * @brief List names of current loaded modules, splited with '\n'
 *
 * @param fd: supercall fd
 * @param names_buf : output buffer
 * @param buf_len : the length of names_buf
 * @return long : the length of result string if succeed, negative if failed
 */
static inline long sc_kpm_list(int fd, char *names_buf, int buf_len)
{
    if (!names_buf || buf_len <= 0) return -EINVAL;
    struct {
        int len;
        char buf[4096];
    } kargs;
    kargs.len = buf_len;
    long ret = ioctl(fd, SUPERCALL_KPM_LIST, &kargs);
    if (ret > 0) memcpy(names_buf, kargs.buf, ret);
    return ret;
}

/**
 * @brief Get module information.
 *
 * @param fd: supercall fd
 * @param name : module name
 * @param buf
 * @param buf_len
 * @return long : The length of result string if succeed, negative if failed
 */
static inline long sc_kpm_info(int fd, const char *name, char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -EINVAL;
    struct {
        char name[64];
        int out_len;
        char out_buf[4096];
    } kargs;
    memset(&kargs, 0, sizeof(kargs));
    strncpy(kargs.name, name, sizeof(kargs.name) - 1);
    kargs.out_len = buf_len;
    long ret = ioctl(fd, SUPERCALL_KPM_INFO, &kargs);
    if (ret > 0) memcpy(buf, kargs.out_buf, ret > buf_len ? buf_len : ret);
    return ret;
}

/**
 * @brief Write kernel storage
 *
 * @param fd: supercall fd
 * @param gid group id
 * @param did data id
 * @param data
 * @param offset
 * @param dlen
 * @return long
 */
static inline long sc_kstorage_write(int fd, int gid, long did, void *data, int offset, int dlen)
{
    struct kstorage_rw_args {
        int gid;
        long did;
        int offset;
        int dlen;
        char data[0];
    };
    struct kstorage_rw_args *args = static_cast<struct kstorage_rw_args *>(alloca(sizeof(*args) + dlen));
    if (!args) return -ENOMEM;
    args->gid = gid;
    args->did = did;
    args->offset = offset;
    args->dlen = dlen;
    memcpy(args->data, data, dlen);
    return ioctl(fd, SUPERCALL_KSTORAGE_WRITE, args);
}

/**
 * @brief Read kernel storage
 *
 * @param fd: supercall fd
 * @param gid
 * @param did
 * @param out_data
 * @param offset
 * @param dlen
 * @return long
 */
static inline long sc_kstorage_read(int fd, int gid, long did, void *out_data, int offset, int dlen)
{
    struct kstorage_rw_args {
        int gid;
        long did;
        int offset;
        int dlen;
        char data[0];
    };
    struct kstorage_rw_args *args = static_cast<struct kstorage_rw_args *>(alloca(sizeof(*args) + dlen));
    if (!args) return -ENOMEM;
    args->gid = gid;
    args->did = did;
    args->offset = offset;
    args->dlen = dlen;
    long ret = ioctl(fd, SUPERCALL_KSTORAGE_READ, args);
    if (ret >= 0) memcpy(out_data, args->data, dlen);
    return ret;
}

/**
 * @brief List kernel storage IDs
 *
 * @param fd: supercall fd
 * @param gid
 * @param ids
 * @param ids_len
 * @return long numbers of listed ids
 */
static inline long sc_kstorage_list_ids(int fd, int gid, long *ids, int ids_len)
{
    struct kstorage_list_args {
        int gid;
        int ids_len;
        long ids[0];
    };
    struct kstorage_list_args *args = static_cast<struct kstorage_list_args *>(alloca(sizeof(*args) + ids_len * sizeof(long)));
    if (!args) return -ENOMEM;
    args->gid = gid;
    args->ids_len = ids_len;
    long ret = ioctl(fd, SUPERCALL_KSTORAGE_LIST_IDS, args);
    if (ret > 0) memcpy(ids, args->ids, ret * sizeof(long));
    return ret;
}

/**
 * @brief Remove kernel storage
 *
 * @param fd: supercall fd
 * @param gid
 * @param did
 * @return long
 */
static inline long sc_kstorage_remove(int fd, int gid, long did)
{
    struct {
        int gid;
        long did;
    } args = { gid, did };
    return ioctl(fd, SUPERCALL_KSTORAGE_REMOVE, &args);
}

/**
 * @brief Get whether in safe mode
 *
 * @param fd: supercall fd
 * @return long
 */
static inline long sc_su_get_safemode(int fd)
{
    return ioctl(fd, SUPERCALL_SU_GET_SAFEMODE, 0);
}

/**
 * @brief Load APatch package_config from /data/adb/ap/package_config
 *
 * @param fd: supercall fd
 * @return long : number of entries loaded if succeed, negative value if failed
 */
static inline long sc_ap_load_package_config(int fd)
{
    return ioctl(fd, SUPERCALL_AP_LOAD_PACKAGE_CONFIG, 0);
}

static inline long sc_bootlog(int fd)
{
    return ioctl(fd, SUPERCALL_BOOTLOG, 0);
}

static inline long sc_panic(int fd)
{
    return ioctl(fd, SUPERCALL_PANIC, 0);
}

static inline long __sc_test(int fd, long a1, long a2, long a3)
{
    return ioctl(fd, SUPERCALL_TEST, 0);
}

#ifdef ANDROID
static inline long sc_set_ap_mod_exclude(int fd, uid_t uid, int exclude)
{
    if(exclude) {
        return sc_kstorage_write(fd, KSTORAGE_EXCLUDE_LIST_GROUP, uid, &exclude, 0, sizeof(exclude));
    } else {
        return sc_kstorage_remove(fd, KSTORAGE_EXCLUDE_LIST_GROUP, uid);
    }
}

static inline int sc_get_ap_mod_exclude(int fd, uid_t uid)
{
    int exclude = 0;
    int rc = sc_kstorage_read(fd, KSTORAGE_EXCLUDE_LIST_GROUP, uid, &exclude, 0, sizeof(exclude));
    if (rc < 0) return 0;
    return exclude;
}

static inline int sc_list_ap_mod_exclude(int fd, uid_t *uids, int uids_len)
{
    if(uids_len < 0 || uids_len > 512) return -E2BIG;
    long ids[uids_len];
    int rc = sc_kstorage_list_ids(fd, KSTORAGE_EXCLUDE_LIST_GROUP, ids, uids_len);
    if (rc < 0) return 0;
    for(int i = 0; i < rc; i ++) {
        uids[i] = (uid_t)ids[i];
    }
    return rc;
}
#endif

#endif
