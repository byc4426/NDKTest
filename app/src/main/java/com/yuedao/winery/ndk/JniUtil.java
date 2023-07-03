package com.yuedao.winery.ndk;

public class JniUtil {
    static {
        System.loadLibrary("myndktest");
    }

    public static native boolean init();

    public static native String getKey();
}