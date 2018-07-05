package com.newolf.keystoreutilssimple

import android.app.Application
import com.blankj.utilcode.util.Utils
import com.newolf.keystoreutils.AndroidKeyStoreRSAUtils

/**
 * ================================================
 * @author : NeWolf
 * @version : 1.0
 * date :  2018/7/4
 * desc:
 * history:
 * ================================================
 */
class App:Application() {
    override fun onCreate() {
        super.onCreate()

        Utils.init(this)
//        KeyStoreUtils.init(this,packageName,true)
        AndroidKeyStoreRSAUtils.init(this, packageName ,true)
    }
}