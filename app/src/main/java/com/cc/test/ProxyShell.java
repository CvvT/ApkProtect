package com.cc.test;


/**
 * Created by CwT on 15/7/14.
 */
public class ProxyShell {
    static ProxyShell proxyShell;
    public static boolean init = false;

    public static void startshell(String name){
        if (proxyShell == null)
            proxyShell = new ProxyShell();
        proxyShell.start(name);
    }

    public void start(String name){
        if (!init)
            System.loadLibrary("test");
        init = true;
        getStringFromNative(name);
    }

    public native int getStringFromNative(String packagename);
}
