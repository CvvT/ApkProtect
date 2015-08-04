package com.cc.test;

import android.app.Application;
import android.os.Debug;

/**
 * Created by CwT on 15/7/30.
 */
public class myApp extends Application {

    @Override
    public void onCreate(){
        super.onCreate();
//        Debug.waitForDebugger();
    }
}
