/*
 * B46-3A JNI shim: the ONLY code exposed to the JVM for the native
 * tun2socks bridge. It links against libnovatun2socks.so (the Go
 * c-shared artifact built from ../native, see ../scripts/build-c-shared.sh)
 * and is packaged as libnovatun2socks_jni.so.
 *
 * Java surface: net.pocvpn.client.vpn.hysteria.NativeTun2SocksBridge
 *   private static native int nativeStart(int fd, int mtu, String socksAddr)
 *   private static native int nativeStop()
 *   private static native boolean nativeIsStarted()
 *
 * This file does zero packet processing itself - all Go/tun2socks calls
 * are forwarded 1:1 to the exported C functions in libnovatun2socks.h.
 * It never crashes the process on bad input: JNI string extraction is
 * NULL-checked and Go-side validation (see native/main.go) rejects bad
 * fd/mtu/address values with a typed negative code instead of a panic.
 */
#include <jni.h>
#include <string.h>

#include "libnovatun2socks.h"

JNIEXPORT jint JNICALL
Java_net_pocvpn_client_vpn_hysteria_NativeTun2SocksBridge_nativeStart(
    JNIEnv *env, jclass clazz, jint fd, jint mtu, jstring socksAddr) {
    (void)clazz;

    if (socksAddr == NULL) {
        return NovaTun2SocksStart((int)fd, (int)mtu, NULL);
    }

    const char *addr = (*env)->GetStringUTFChars(env, socksAddr, NULL);
    if (addr == NULL) {
        /* OutOfMemoryError already pending on the JVM side. */
        return -4;
    }

    int result = NovaTun2SocksStart((int)fd, (int)mtu, (char *)addr);

    (*env)->ReleaseStringUTFChars(env, socksAddr, addr);
    return (jint)result;
}

JNIEXPORT jint JNICALL
Java_net_pocvpn_client_vpn_hysteria_NativeTun2SocksBridge_nativeStop(
    JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    return (jint)NovaTun2SocksStop();
}

JNIEXPORT jboolean JNICALL
Java_net_pocvpn_client_vpn_hysteria_NativeTun2SocksBridge_nativeIsStarted(
    JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    return NovaTun2SocksIsStarted() != 0 ? JNI_TRUE : JNI_FALSE;
}
