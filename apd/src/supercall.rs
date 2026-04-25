use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read},
    process,
    sync::{Arc, Mutex},
};

use libc::{EINVAL, c_long, c_int, c_void, ioctl, uid_t};
use log::{error, info, warn};

use crate::package::{read_ap_package_config, synchronize_package_uid};

const KP_DEVICE_PATH: &[u8] = b"/dev/kp\0";

const KSTORAGE_EXCLUDE_LIST_GROUP: i32 = 1;

const SUPERCALL_HELLO: c_int = 0x1000;
const SUPERCALL_SU: c_int = 0x1010;
const SUPERCALL_KSTORAGE_WRITE: c_int = 0x1041;
const SUPERCALL_KSTORAGE_READ: c_int = 0x1042;
const SUPERCALL_KSTORAGE_LIST_IDS: c_int = 0x1043;
const SUPERCALL_KSTORAGE_REMOVE: c_int = 0x1044;
const SUPERCALL_SU_GRANT_UID: c_int = 0x1100;
const SUPERCALL_SU_REVOKE_UID: c_int = 0x1101;
const SUPERCALL_SU_NUMS: c_int = 0x1102;
const SUPERCALL_SU_LIST: c_int = 0x1103;
const SUPERCALL_SU_RESET_PATH: c_int = 0x1111;
const SUPERCALL_SU_GET_SAFEMODE: c_int = 0x1112;
const SUPERCALL_HELLO_MAGIC: c_int = 0x11581158;

const SUPERCALL_SCONTEXT_LEN: usize = 0x60;

#[repr(C)]
struct SuProfile {
    uid: i32,
    to_uid: i32,
    scontext: [u8; SUPERCALL_SCONTEXT_LEN],
}

#[repr(C)]
struct KstorageWriteArgs {
    gid: i32,
    did: i64,
    offset: i32,
    dlen: i32,
    data: [u8; 0],
}

#[repr(C)]
struct KstorageReadArgs {
    gid: i32,
    did: i64,
    offset: i32,
    dlen: i32,
    data: [u8; 0],
}

#[repr(C)]
struct KstorageListIdsArgs {
    gid: i32,
    ids_len: i32,
    ids: [i64; 0],
}

#[repr(C)]
struct KstorageRemoveArgs {
    gid: i32,
    did: i64,
}

#[repr(C)]
struct SuRevokeUidArgs {
    uid: uid_t,
}

#[repr(C)]
struct SuListArgs {
    num: i32,
    uids: *mut uid_t,
}

pub fn sc_get_fd() -> i32 {
    unsafe { libc::open(KP_DEVICE_PATH.as_ptr() as *const _, libc::O_RDWR) }
}

pub fn sc_ready(fd: i32) -> bool {
    unsafe { ioctl(fd, SUPERCALL_HELLO, 0) == SUPERCALL_HELLO_MAGIC }
}

fn sc_su(fd: i32, profile: &SuProfile) -> c_long {
    unsafe { ioctl(fd, SUPERCALL_SU, profile as *const SuProfile as c_long) as c_long }
}

fn sc_su_grant_uid(fd: i32, profile: &SuProfile) -> c_long {
    unsafe { ioctl(fd, SUPERCALL_SU_GRANT_UID, profile as *const SuProfile as c_long) as c_long }
}

fn sc_su_revoke_uid(fd: i32, uid: uid_t) -> c_long {
    let args = SuRevokeUidArgs { uid };
    unsafe { ioctl(fd, SUPERCALL_SU_REVOKE_UID, &args as *const SuRevokeUidArgs as c_long) as c_long }
}

fn sc_kstorage_write(
    fd: i32,
    gid: i32,
    did: i64,
    data: *mut c_void,
    offset: i32,
    dlen: i32,
) -> c_long {
    let layout = std::alloc::Layout::from_size_align(
        std::mem::size_of::<KstorageWriteArgs>() + dlen as usize,
        std::mem::align_of::<KstorageWriteArgs>(),
    )
    .unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) as *mut KstorageWriteArgs };
    if ptr.is_null() {
        return -(EINVAL as c_long);
    }
    unsafe {
        (*ptr).gid = gid;
        (*ptr).did = did;
        (*ptr).offset = offset;
        (*ptr).dlen = dlen;
        std::ptr::copy_nonoverlapping(data as *const u8, (*ptr).data.as_mut_ptr(), dlen as usize);
    }
    let ret = unsafe { ioctl(fd, SUPERCALL_KSTORAGE_WRITE, ptr as c_long) as c_long };
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout) };
    ret
}

fn sc_kstorage_read(
    fd: i32,
    gid: i32,
    did: i64,
    out_data: *mut c_void,
    offset: i32,
    dlen: i32,
) -> c_long {
    let layout = std::alloc::Layout::from_size_align(
        std::mem::size_of::<KstorageReadArgs>() + dlen as usize,
        std::mem::align_of::<KstorageReadArgs>(),
    )
    .unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) as *mut KstorageReadArgs };
    if ptr.is_null() {
        return -(EINVAL as c_long);
    }
    unsafe {
        (*ptr).gid = gid;
        (*ptr).did = did;
        (*ptr).offset = offset;
        (*ptr).dlen = dlen;
    }
    let ret = unsafe { ioctl(fd, SUPERCALL_KSTORAGE_READ, ptr as c_long) as c_long };
    if ret >= 0 {
        unsafe {
            std::ptr::copy_nonoverlapping((*ptr).data.as_ptr(), out_data as *mut u8, dlen as usize);
        }
    }
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout) };
    ret
}

fn sc_kstorage_list_ids(fd: i32, gid: i32, ids: &mut [i64]) -> c_long {
    let ids_len = ids.len() as i32;
    let layout = std::alloc::Layout::from_size_align(
        std::mem::size_of::<KstorageListIdsArgs>() + ids_len as usize * std::mem::size_of::<i64>(),
        std::mem::align_of::<KstorageListIdsArgs>(),
    )
    .unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) as *mut KstorageListIdsArgs };
    if ptr.is_null() {
        return -(EINVAL as c_long);
    }
    unsafe {
        (*ptr).gid = gid;
        (*ptr).ids_len = ids_len;
    }
    let ret = unsafe { ioctl(fd, SUPERCALL_KSTORAGE_LIST_IDS, ptr as c_long) as c_long };
    if ret > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(
                (*ptr).ids.as_ptr(),
                ids.as_mut_ptr(),
                ret as usize * std::mem::size_of::<i64>(),
            );
        }
    }
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout) };
    ret
}

fn sc_kstorage_remove(fd: i32, gid: i32, did: i64) -> c_long {
    let args = KstorageRemoveArgs { gid, did };
    unsafe { ioctl(fd, SUPERCALL_KSTORAGE_REMOVE, &args as *const KstorageRemoveArgs as c_long) as c_long }
}

fn sc_set_ap_mod_exclude(fd: i32, uid: i64, exclude: i32) -> c_long {
    if exclude != 0 {
        sc_kstorage_write(
            fd,
            KSTORAGE_EXCLUDE_LIST_GROUP,
            uid,
            &exclude as *const i32 as *mut c_void,
            0,
            std::mem::size_of::<i32>() as i32,
        )
    } else {
        sc_kstorage_remove(fd, KSTORAGE_EXCLUDE_LIST_GROUP, uid)
    }
}

pub fn sc_su_get_safemode(fd: i32) -> c_long {
    unsafe { ioctl(fd, SUPERCALL_SU_GET_SAFEMODE, 0) as c_long }
}

fn sc_su_uid_nums(fd: i32) -> c_long {
    unsafe { ioctl(fd, SUPERCALL_SU_NUMS, 0) as c_long }
}

fn sc_su_allow_uids(fd: i32, buf: &mut [uid_t]) -> c_long {
    if buf.is_empty() {
        return -(EINVAL as c_long);
    }
    let args = SuListArgs {
        num: buf.len() as i32,
        uids: buf.as_mut_ptr(),
    };
    unsafe { ioctl(fd, SUPERCALL_SU_LIST, &args as *const SuListArgs as c_long) as c_long }
}

fn sc_su_reset_path(fd: i32, path: &CStr) -> c_long {
    unsafe { ioctl(fd, SUPERCALL_SU_RESET_PATH, path.as_ptr() as c_long) as c_long }
}

fn read_file_to_string(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn convert_string_to_u8_array(s: &str) -> [u8; SUPERCALL_SCONTEXT_LEN] {
    let mut u8_array = [0u8; SUPERCALL_SCONTEXT_LEN];
    let bytes = s.as_bytes();
    let len = usize::min(SUPERCALL_SCONTEXT_LEN, bytes.len());
    u8_array[..len].copy_from_slice(&bytes[..len]);
    u8_array
}

pub fn refresh_ap_package_list(fd: i32, mutex: &Arc<Mutex<()>>) {
    let _lock = mutex.lock().unwrap();

    let num = sc_su_uid_nums(fd);
    if num < 0 {
        error!("[refresh_su_list] Error getting number of UIDs: {}", num);
        return;
    }
    let num = num as usize;
    let mut uids = vec![0 as uid_t; num];
    let n = sc_su_allow_uids(fd, &mut uids);
    if n < 0 {
        error!("[refresh_su_list] Error getting su list");
        return;
    }
    for uid in &uids {
        if *uid == 0 || *uid == 2000 {
            warn!(
                "[refresh_ap_package_list] Skip revoking critical uid: {}",
                uid
            );
            continue;
        }
        info!(
            "[refresh_ap_package_list] Revoking {} root permission...",
            uid
        );
        let rc = sc_su_revoke_uid(fd, *uid);
        if rc != 0 {
            error!("[refresh_ap_package_list] Error revoking UID: {}", rc);
        }
    }

    if let Err(e) = synchronize_package_uid() {
        error!("Failed to synchronize package UIDs: {}", e);
    }

    let package_configs = read_ap_package_config();
    for config in package_configs {
        if config.allow == 1 && config.exclude == 0 {
            let profile = SuProfile {
                uid: config.uid,
                to_uid: config.to_uid,
                scontext: convert_string_to_u8_array(&config.sctx),
            };
            let result = sc_su_grant_uid(fd, &profile);
            info!(
                "[refresh_ap_package_list] Loading {}: result = {}",
                config.pkg, result
            );
        }
        if config.allow == 0 && config.exclude == 1 {
            let result = sc_set_ap_mod_exclude(fd, config.uid as i64, 1);
            info!(
                "[refresh_ap_package_list] Loading exclude {}: result = {}",
                config.pkg, result
            );
        }
    }
}

pub fn privilege_apd_profile(fd: i32) {
    let all_allow_ctx = "u:r:magisk:s0";
    let profile = SuProfile {
        uid: process::id().try_into().expect("PID conversion failed"),
        to_uid: 0,
        scontext: convert_string_to_u8_array(all_allow_ctx),
    };
    let result = sc_su(fd, &profile);
    info!("[privilege_apd_profile] result = {}", result);
}

pub fn init_load_su_path(fd: i32) {
    let su_path_file = "/data/adb/ap/su_path";

    match read_file_to_string(su_path_file) {
        Ok(su_path) => {
            match CString::new(su_path.trim()) {
                Ok(su_path_cstr) => {
                    let result = sc_su_reset_path(fd, &su_path_cstr);
                    if result == 0 {
                        info!("suPath load successfully");
                    } else {
                        warn!("Failed to load su path, error code: {}", result);
                    }
                }
                Err(e) => {
                    warn!("Failed to convert su_path: {}", e);
                }
            }
        }
        Err(e) => {
            warn!("Failed to read su_path file: {}", e);
        }
    }
}
