package com.newolf.keystoreutilssimple

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.text.TextUtils
import android.util.Base64
import android.view.View
import com.blankj.utilcode.util.LogUtils
import com.blankj.utilcode.util.SPUtils
import com.blankj.utilcode.util.ToastUtils
import com.newolf.keystoreutils.AndroidKeyStoreRSAUtils
import kotlinx.android.synthetic.main.activity_decrypt.*

class DecryptActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_decrypt)

        val s =   SPUtils.getInstance().getString("key")

        LogUtils.e(s)

        btnOK.setOnClickListener(View.OnClickListener {


            if (!TextUtils.isEmpty(s)){
                try {
                    val decrypt = AndroidKeyStoreRSAUtils.decryptByPrivateKeyForSpilt(Base64.decode(s,Base64.DEFAULT))

                    val decryptStr = String(decrypt)


                    ToastUtils.showLong(decryptStr)
                } catch (e: Exception) {
                    SPUtils.getInstance().clear()
                }

            }else{
                ToastUtils.showLong("s == null")
            }

        })

    }



}
