package com.newolf.keystoreutilssimple

import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.text.TextUtils
import android.util.Base64
import android.view.View
import com.blankj.utilcode.util.LogUtils
import com.blankj.utilcode.util.SPUtils
import com.newolf.keystoreutils.AndroidKeyStoreRSAUtils
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        var s = "{no = '123456789', pwd = '123123',sss = '控件和那接口萨克斯的返回康师傅就能看大手大脚看空间' }"


        try {



            val encrypt = AndroidKeyStoreRSAUtils.encryptByPublicKey(s.toByteArray(),AndroidKeyStoreRSAUtils.getLocalPublicKey().encoded)

            var encryptString = String(Base64.encode(encrypt,Base64.DEFAULT))

            var get =   SPUtils.getInstance().getString("key")

            if (TextUtils.isEmpty(get)){
                LogUtils.e(encryptString)
                SPUtils.getInstance().put("key",encryptString)
            }else {
//                encryptString = get
//                SPUtils.getInstance().clear()
            }




            val decrypt =AndroidKeyStoreRSAUtils.decryptByPrivateKey(Base64.decode(encryptString,Base64.DEFAULT))

            val decryptStr = String(decrypt)

//

            tvShow.setText("元数据 = $s\r\n 加密后的数据串 = $encryptString\r\n  再解密 = $decryptStr 是否还原了呢 ? = ${s == decryptStr}")
        } catch (e: Exception) {
            e.printStackTrace()
        }


        btnNext.setOnClickListener(View.OnClickListener { startActivity(Intent(this,DecryptActivity::class.java)) })

    }


}
