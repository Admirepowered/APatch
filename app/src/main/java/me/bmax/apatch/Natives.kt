package me.bmax.apatch

import android.os.Parcelable
import androidx.annotation.Keep
import androidx.compose.runtime.Immutable
import dalvik.annotation.optimization.FastNative
import kotlinx.parcelize.Parcelize

object Natives {
    init {
        System.loadLibrary("apjni")
    }

    @Immutable
    @Parcelize
    @Keep
    data class Profile(
        var uid: Int = 0,
        var toUid: Int = 0,
        var scontext: String = APApplication.DEFAULT_SCONTEXT,
    ) : Parcelable

    @Keep
    class KPMCtlRes {
        var rc: Long = 0
        var outMsg: String? = null

        constructor()

        constructor(rc: Long, outMsg: String?) {
            this.rc = rc
            this.outMsg = outMsg
        }
    }

    @FastNative
    external fun nativeGetFd(): Int

    @FastNative
    external fun nativeCloseFd(fd: Int)

    @FastNative
    private external fun nativeSu(fd: Int, toUid: Int, scontext: String?): Long

    fun su(toUid: Int, scontext: String?): Boolean {
        return nativeSu(APApplication.scFd, toUid, scontext) == 0L
    }

    fun su(): Boolean {
        return su(0, "")
    }

    @FastNative
    external fun nativeReady(fd: Int): Boolean

    @FastNative
    private external fun nativeSuPath(fd: Int): String

    fun suPath(): String {
        return nativeSuPath(APApplication.scFd)
    }

    @FastNative
    private external fun nativeSuUids(fd: Int): IntArray

    fun suUids(): IntArray {
        return nativeSuUids(APApplication.scFd)
    }

    @FastNative
    private external fun nativeKernelPatchVersion(fd: Int): Long
    fun kernelPatchVersion(): Long {
        return nativeKernelPatchVersion(APApplication.scFd)
    }

    @FastNative
    private external fun nativeKernelPatchBuildTime(fd: Int): String
    fun kernelPatchBuildTime(): String {
        return nativeKernelPatchBuildTime(APApplication.scFd)
    }

    private external fun nativeLoadKernelPatchModule(
        fd: Int, modulePath: String, args: String
    ): Long

    fun loadKernelPatchModule(modulePath: String, args: String): Long {
        return nativeLoadKernelPatchModule(APApplication.scFd, modulePath, args)
    }

    private external fun nativeUnloadKernelPatchModule(fd: Int, moduleName: String): Long
    fun unloadKernelPatchModule(moduleName: String): Long {
        return nativeUnloadKernelPatchModule(APApplication.scFd, moduleName)
    }

    @FastNative
    private external fun nativeKernelPatchModuleNum(fd: Int): Long

    fun kernelPatchModuleNum(): Long {
        return nativeKernelPatchModuleNum(APApplication.scFd)
    }

    @FastNative
    private external fun nativeKernelPatchModuleList(fd: Int): String
    fun kernelPatchModuleList(): String {
        return nativeKernelPatchModuleList(APApplication.scFd)
    }

    @FastNative
    private external fun nativeKernelPatchModuleInfo(fd: Int, moduleName: String): String
    fun kernelPatchModuleInfo(moduleName: String): String {
        return nativeKernelPatchModuleInfo(APApplication.scFd, moduleName)
    }

    private external fun nativeControlKernelPatchModule(
        fd: Int, modName: String, jctlargs: String
    ): KPMCtlRes

    fun kernelPatchModuleControl(moduleName: String, controlArg: String): KPMCtlRes {
        return nativeControlKernelPatchModule(APApplication.scFd, moduleName, controlArg)
    }

    @FastNative
    private external fun nativeGrantSu(
        fd: Int, uid: Int, toUid: Int, scontext: String?
    ): Long

    fun grantSu(uid: Int, toUid: Int, scontext: String?): Long {
        return nativeGrantSu(APApplication.scFd, uid, toUid, scontext)
    }

    @FastNative
    private external fun nativeRevokeSu(fd: Int, uid: Int): Long
    fun revokeSu(uid: Int): Long {
        return nativeRevokeSu(APApplication.scFd, uid)
    }

    @FastNative
    private external fun nativeSetUidExclude(fd: Int, uid: Int, exclude: Int): Int
    fun setUidExclude(uid: Int, exclude: Int): Int {
        return nativeSetUidExclude(APApplication.scFd, uid, exclude)
    }

    @FastNative
    private external fun nativeGetUidExclude(fd: Int, uid: Int): Int
    fun isUidExcluded(uid: Int): Int {
        return nativeGetUidExclude(APApplication.scFd, uid)
    }

    @FastNative
    private external fun nativeSuProfile(fd: Int, uid: Int): Profile
    fun suProfile(uid: Int): Profile {
        return nativeSuProfile(APApplication.scFd, uid)
    }

    @FastNative
    private external fun nativeResetSuPath(fd: Int, path: String): Boolean
    fun resetSuPath(path: String): Boolean {
        return nativeResetSuPath(APApplication.scFd, path)
    }
}
