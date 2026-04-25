/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2024 GarfieldHan. All Rights Reserved.
 * Copyright (C) 2024 1f2003d5. All Rights Reserved.
 */

#include <cstring>
#include <vector>

#include "apjni.hpp"
#include "supercall.h"

jint nativeGetFd(JNIEnv *env, jobject /* this */) {
    int fd = sc_get_fd();
    if (fd < 0) [[unlikely]] {
        LOGE("nativeGetFd error: %d", fd);
    }
    return fd;
}

void nativeCloseFd(JNIEnv *env, jobject /* this */, jint fd) {
    if (fd >= 0) {
        close(fd);
    }
}

jboolean nativeReady(JNIEnv *env, jobject /* this */, jint fd) {
    ensureFdValid(fd);
    return sc_ready(fd);
}

jlong nativeKernelPatchVersion(JNIEnv *env, jobject /* this */, jint fd) {
    ensureFdValid(fd);
    return sc_kp_ver(fd);
}

jstring nativeKernelPatchBuildTime(JNIEnv *env, jobject /* this */, jint fd) {
    ensureFdValid(fd);
    char buf[4096] = { '\0' };
    sc_kp_buildtime(fd, buf, sizeof(buf));
    return env->NewStringUTF(buf);
}

jlong nativeSu(JNIEnv *env, jobject /* this */, jint fd, jint to_uid, jstring selinux_context_jstr) {
    ensureFdValid(fd);
    const char *selinux_context = nullptr;
    if (selinux_context_jstr) selinux_context = JUTFString(env, selinux_context_jstr);
    struct su_profile profile{};
    profile.uid = getuid();
    profile.to_uid = (uid_t)to_uid;
    if (selinux_context) strncpy(profile.scontext, selinux_context, sizeof(profile.scontext) - 1);
    long rc = sc_su(fd, &profile);
    if (rc < 0) [[unlikely]] {
        LOGE("nativeSu error: %ld", rc);
    }

    return rc;
}

jint nativeSetUidExclude(JNIEnv *env, jobject /* this */, jint fd, jint uid, jint exclude) {
    ensureFdValid(fd);
    return static_cast<int>(sc_set_ap_mod_exclude(fd, (uid_t) uid, exclude));
}

jint nativeGetUidExclude(JNIEnv *env, jobject /* this */, jint fd, uid_t uid) {
    ensureFdValid(fd);
    return static_cast<int>(sc_get_ap_mod_exclude(fd, uid));
}

jintArray nativeSuUids(JNIEnv *env, jobject /* this */, jint fd) {
    ensureFdValid(fd);
    int num = static_cast<int>(sc_su_uid_nums(fd));

    if (num <= 0) [[unlikely]] {
        LOGW("SuperUser Count less than 1, skip allocating vector...");
        return env->NewIntArray(0);
    }

    std::vector<int> uids(num);

    long n = sc_su_allow_uids(fd, (uid_t *) uids.data(), num);
    if (n > 0) [[unlikely]] {
        auto array = env->NewIntArray(n);
        env->SetIntArrayRegion(array, 0, n, uids.data());
        return array;
    }

    return env->NewIntArray(0);
}

jobject nativeSuProfile(JNIEnv *env, jobject /* this */, jint fd, jint uid) {
    ensureFdValid(fd);
    struct su_profile profile{};
    long rc = sc_su_uid_profile(fd, (uid_t) uid, &profile);
    if (rc < 0) [[unlikely]] {
        LOGE("nativeSuProfile error: %ld\n", rc);
        return nullptr;
    }
    jclass cls = env->FindClass("me/bmax/apatch/Natives$Profile");
    jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
    jfieldID uidField = env->GetFieldID(cls, "uid", "I");
    jfieldID toUidField = env->GetFieldID(cls, "toUid", "I");
    jfieldID scontextFild = env->GetFieldID(cls, "scontext", "Ljava/lang/String;");

    jobject obj = env->NewObject(cls, constructor);
    env->SetIntField(obj, uidField, (int) profile.uid);
    env->SetIntField(obj, toUidField, (int) profile.to_uid);
    env->SetObjectField(obj, scontextFild, env->NewStringUTF(profile.scontext));

    return obj;
}

jlong nativeLoadKernelPatchModule(JNIEnv *env, jobject /* this */, jint fd, jstring module_path_jstr, jstring args_jstr) {
    ensureFdValid(fd);
    const auto module_path = JUTFString(env, module_path_jstr);
    const auto args = JUTFString(env, args_jstr);
    long rc = sc_kpm_load(fd, module_path.get(), args.get(), nullptr);
    if (rc < 0) [[unlikely]] {
        LOGE("nativeLoadKernelPatchModule error: %ld", rc);
    }

    return rc;
}

jobject nativeControlKernelPatchModule(JNIEnv *env, jobject /* this */, jint fd, jstring module_name_jstr, jstring control_args_jstr) {
    ensureFdValid(fd);
    const auto module_name = JUTFString(env, module_name_jstr);
    const auto control_args = JUTFString(env, control_args_jstr);

    char buf[4096] = { '\0' };
    long rc = sc_kpm_control(fd, module_name.get(), control_args.get(), buf, sizeof(buf));
    if (rc < 0) [[unlikely]] {
        LOGE("nativeControlKernelPatchModule error: %ld", rc);
    }

    jclass cls = env->FindClass("me/bmax/apatch/Natives$KPMCtlRes");
    jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
    jfieldID rcField = env->GetFieldID(cls, "rc", "J");
    jfieldID outMsg = env->GetFieldID(cls, "outMsg", "Ljava/lang/String;");

    jobject obj = env->NewObject(cls, constructor);
    env->SetLongField(obj, rcField, rc);
    env->SetObjectField(obj, outMsg, env->NewStringUTF(buf));

    return obj;
}

jlong nativeUnloadKernelPatchModule(JNIEnv *env, jobject /* this */, jint fd, jstring module_name_jstr) {
    ensureFdValid(fd);
    const auto module_name = JUTFString(env, module_name_jstr);
    long rc = sc_kpm_unload(fd, module_name.get(), nullptr);
    if (rc < 0) [[unlikely]] {
        LOGE("nativeUnloadKernelPatchModule error: %ld", rc);
    }

    return rc;
}

jlong nativeKernelPatchModuleNum(JNIEnv *env, jobject /* this */, jint fd) {
    ensureFdValid(fd);
    long rc = sc_kpm_nums(fd);
    if (rc < 0) [[unlikely]] {
        LOGE("nativeKernelPatchModuleNum error: %ld", rc);
    }

    return rc;
}

jstring nativeKernelPatchModuleList(JNIEnv *env, jobject /* this */, jint fd) {
    ensureFdValid(fd);
    char buf[4096] = { '\0' };
    long rc = sc_kpm_list(fd, buf, sizeof(buf));
    if (rc < 0) [[unlikely]] {
        LOGE("nativeKernelPatchModuleList error: %ld", rc);
    }

    return env->NewStringUTF(buf);
}

jstring nativeKernelPatchModuleInfo(JNIEnv *env, jobject /* this */, jint fd, jstring module_name_jstr) {
    ensureFdValid(fd);
    const auto module_name = JUTFString(env, module_name_jstr);
    char buf[1024] = { '\0' };
    long rc = sc_kpm_info(fd, module_name.get(), buf, sizeof(buf));
    if (rc < 0) [[unlikely]] {
        LOGE("nativeKernelPatchModuleInfo error: %ld", rc);
    }

    return env->NewStringUTF(buf);
}

jlong nativeGrantSu(JNIEnv *env, jobject /* this */, jint fd, jint uid, jint to_uid, jstring selinux_context_jstr) {
    ensureFdValid(fd);
    const auto selinux_context = JUTFString(env, selinux_context_jstr);
    struct su_profile profile{};
    profile.uid = uid;
    profile.to_uid = to_uid;
    if (selinux_context) strncpy(profile.scontext, selinux_context, sizeof(profile.scontext) - 1);
    return sc_su_grant_uid(fd, &profile);
}

jlong nativeRevokeSu(JNIEnv *env, jobject /* this */, jint fd, jint uid) {
    ensureFdValid(fd);
    return sc_su_revoke_uid(fd, (uid_t) uid);
}

jstring nativeSuPath(JNIEnv *env, jobject /* this */, jint fd) {
    ensureFdValid(fd);
    char buf[SU_PATH_MAX_LEN] = { '\0' };
    long rc = sc_su_get_path(fd, buf, sizeof(buf));
    if (rc < 0) [[unlikely]] {
        LOGE("nativeSuPath error: %ld", rc);
    }

    return env->NewStringUTF(buf);
}

jboolean nativeResetSuPath(JNIEnv *env, jobject /* this */, jint fd, jstring su_path_jstr) {
    ensureFdValid(fd);
    const auto su_path = JUTFString(env, su_path_jstr);
    return sc_su_reset_path(fd, su_path.get()) == 0;
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void * /*reserved*/) {
    LOGI("Enter OnLoad");

    JNIEnv* env{};
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) [[unlikely]] {
        LOGE("Get JNIEnv error!");
        return JNI_FALSE;
    }

    auto clazz = JNI_FindClass(env, "me/bmax/apatch/Natives");
    if (clazz.get() == nullptr) [[unlikely]] {
        LOGE("Failed to find Natives class");
        return JNI_FALSE;
    }

    const static JNINativeMethod gMethods[] = {
        {"nativeGetFd", "()I", reinterpret_cast<void *>(&nativeGetFd)},
        {"nativeCloseFd", "(I)V", reinterpret_cast<void *>(&nativeCloseFd)},
        {"nativeReady", "(I)Z", reinterpret_cast<void *>(&nativeReady)},
        {"nativeKernelPatchVersion", "(I)J", reinterpret_cast<void *>(&nativeKernelPatchVersion)},
        {"nativeKernelPatchBuildTime", "(I)Ljava/lang/String;", reinterpret_cast<void *>(&nativeKernelPatchBuildTime)},
        {"nativeSu", "(IILjava/lang/String;)J", reinterpret_cast<void *>(&nativeSu)},
        {"nativeSetUidExclude", "(III)I", reinterpret_cast<void *>(&nativeSetUidExclude)},
        {"nativeGetUidExclude", "(II)I", reinterpret_cast<void *>(&nativeGetUidExclude)},
        {"nativeSuUids", "(I)[I", reinterpret_cast<void *>(&nativeSuUids)},
        {"nativeSuProfile", "(II)Lme/bmax/apatch/Natives$Profile;", reinterpret_cast<void *>(&nativeSuProfile)},
        {"nativeLoadKernelPatchModule", "(ILjava/lang/String;Ljava/lang/String;)J", reinterpret_cast<void *>(&nativeLoadKernelPatchModule)},
        {"nativeControlKernelPatchModule", "(ILjava/lang/String;Ljava/lang/String;)Lme/bmax/apatch/Natives$KPMCtlRes;", reinterpret_cast<void *>(&nativeControlKernelPatchModule)},
        {"nativeUnloadKernelPatchModule", "(ILjava/lang/String;)J", reinterpret_cast<void *>(&nativeUnloadKernelPatchModule)},
        {"nativeKernelPatchModuleNum", "(I)J", reinterpret_cast<void *>(&nativeKernelPatchModuleNum)},
        {"nativeKernelPatchModuleList", "(I)Ljava/lang/String;", reinterpret_cast<void *>(&nativeKernelPatchModuleList)},
        {"nativeKernelPatchModuleInfo", "(ILjava/lang/String;)Ljava/lang/String;", reinterpret_cast<void *>(&nativeKernelPatchModuleInfo)},
        {"nativeGrantSu", "(IIILjava/lang/String;)J", reinterpret_cast<void *>(&nativeGrantSu)},
        {"nativeRevokeSu", "(II)J", reinterpret_cast<void *>(&nativeRevokeSu)},
        {"nativeSuPath", "(I)Ljava/lang/String;", reinterpret_cast<void *>(&nativeSuPath)},
        {"nativeResetSuPath", "(ILjava/lang/String;)Z", reinterpret_cast<void *>(&nativeResetSuPath)},
    };

    if (JNI_RegisterNatives(env, clazz, gMethods, sizeof(gMethods) / sizeof(gMethods[0])) < 0) [[unlikely]] {
        LOGE("Failed to register native methods");
        return JNI_FALSE;
    }

    LOGI("JNI_OnLoad Done!");
    return JNI_VERSION_1_6;
}
