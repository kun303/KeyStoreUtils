package com.newolf.keystoreutils;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import com.newolf.keystoreutils.constants.SecurityConstants;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

/**
 * ================================================
 *
 * @author : NeWolf
 * @version : 1.0
 * date :  2018/7/4
 * desc:
 * history:
 * ================================================
 */
public class KeyStoreUtils {
    private static final String TAG = KeyStoreUtils.class.getSimpleName();
    private static final int VALUE_1337 = 1337;
    private static String ALIAS;
    private static boolean mLogEnable;
    private static KeyPair mKp;
    private static final int DEFAULT_KEY_SIZE = 2048;//秘钥默认长度
    private static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";//加密填充方式

    public static void init(@NonNull Context context, @NonNull String alias, boolean logEnable) {
        ALIAS = alias+TAG;
        mLogEnable = logEnable;
        logThis(String.format("alias = %1$s ", alias));


        if (!isHaveKeyStore()){
            logThis("need generateRSAKeyPair ");
            try {
                createKeys(context.getApplicationContext());
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
                logThis(e.toString());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                logThis(e.toString());
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
                logThis(e.toString());
            }
        }else{
            logThis("已经有秘钥对了 ");
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    private static void createKeys(Context context) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        //创建一个开始和结束时间,有效范围内的密钥对才会生成。
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        //往后加一年
        end.add(Calendar.YEAR, 1);
        AlgorithmParameterSpec spec;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            //使用别名来检索的key 。这是一个key 的key !
            spec = new KeyPairGeneratorSpec.Builder(context)
                    //使用别名来检索的关键。这是一个关键的关键!
                    .setAlias(ALIAS)
                    // 用于生成自签名证书的主题 X500Principal 接受 RFC 1779/2253的专有名词
                    .setSubject(new X500Principal("CN=" + ALIAS))
                    //用于自签名证书的序列号生成的一对。
                    .setSerialNumber(BigInteger.valueOf(VALUE_1337))
                    // 签名在有效日期范围内
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
        } else {
            //Android 6.0(或者以上)使用KeyGenparameterSpec.Builder 方式来创建,
            // 允许你自定义允许的的关键属性和限制
//            String AES_MODE_CBC = KeyProperties.KEY_ALGORITHM_AES + "/" +
//                    KeyProperties.BLOCK_MODE_CBC + "/" +
//                    KeyProperties.ENCRYPTION_PADDING_PKCS7;
            spec = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN
                    | KeyProperties.PURPOSE_VERIFY
                    | KeyProperties.PURPOSE_ENCRYPT
                    | KeyProperties.PURPOSE_DECRYPT)
//                    .setKeySize(DEFAULT_KEY_SIZE)
                    .setUserAuthenticationRequired(false)
                    .setCertificateSubject(new X500Principal("CN=" + ALIAS))
                    .setDigests(KeyProperties.DIGEST_SHA256 ,KeyProperties.DIGEST_SHA512)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM, KeyProperties.BLOCK_MODE_CTR,
                            KeyProperties.BLOCK_MODE_CBC, KeyProperties.BLOCK_MODE_ECB)
//                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM,CTR/CBC/ECB)
                    .setCertificateSerialNumber(BigInteger.valueOf(VALUE_1337))
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .build();


        }


        KeyPairGenerator kpGenerator = KeyPairGenerator
                .getInstance(SecurityConstants.TYPE_RSA,
                        SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

        kpGenerator.initialize(spec);
        mKp = kpGenerator.generateKeyPair();
        logThis("公共密钥: " + getEncodedString(mKp.getPublic().getEncoded()));
        logThis("私钥: " + mKp.getPublic());

    }


    private static String getEncodedString(byte[] bytes) {

        if (bytes == null) {
            return "";
        } else {
            return new String(
                    Base64.encode(bytes, Base64.NO_WRAP));
        }

    }


    /**
     * 判断是否创建过秘钥
     *
     * @return boolean
     */
    public static boolean isHaveKeyStore() {


        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            // Load the key pair from the Android Key Store
            //从Android加载密钥对密钥存储库中
            KeyStore.Entry entry = ks.getEntry(ALIAS, null);
            if (entry == null) {
                return false;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
            return false;
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }


    public static String signData(@NonNull String inputStr) {
        if (ALIAS == null) {
            throw new RuntimeException("You must init first");
        }
        byte[] data = inputStr.getBytes();
        String result = "";
        try {

            //AndroidKeyStore
            KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
            // 如果你没有InputStream加载,你仍然需要
            //称之为“负载”,或者它会崩溃
            ks.load(null);

            //从Android加载密钥对密钥存储库中
            KeyStore.Entry entry = ks.getEntry(ALIAS, null);
            /* *
             *进行判断处理钥匙是不是存储的当前别名下 不存在要遍历别名列表Keystore.aliases()
             */
            if (entry == null) {
                logThis("No key found under alias: " + ALIAS);
                return result;
            }
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                logThis("Not an instance of a PrivateKeyEntry");
                return result;
            }
            // 开始签名
            Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);
            //初始化使用指定的私钥签名
            s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
            // 签名并存储结果作为Base64编码的字符串。
            s.update(data);
            byte[] signature = s.sign();
            result = Base64.encodeToString(signature, Base64.DEFAULT);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            logThis(e.toString());
            return result;
        }
    }


    public static boolean verifyData(@NonNull String input, @NonNull String signatureStr) {

        if (ALIAS == null) {
            throw new RuntimeException("You must init first");
        }

        //要验证的数据
        byte[] data = input.getBytes();
        //签名
        byte[] signature;


        try {
            //Base64解码字符串
            signature = Base64.decode(signatureStr, Base64.DEFAULT);

            KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
            ks.load(null);

            // Load the key pair from the Android Key Store

            //从Android加载密钥对密钥存储库中
            KeyStore.Entry entry = ks.getEntry(ALIAS, null);
            if (entry == null) {
                logThis("No key found under alias: " + ALIAS);
                return false;
            }
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                logThis("Not an instance of a PrivateKeyEntry");
                return false;
            }
            Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);
            // 开始校验签名
            s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
            s.update(data);
            return s.verify(signature);

        } catch (Exception e) {
            e.printStackTrace();
            logThis(e.toString());
            return false;
        }

    }


    /**
     * 使用私钥进行解密
     */
    public static byte[] decryptByPrivateKey(byte[] encrypted) throws Exception {


        if (ALIAS == null) {
            throw new RuntimeException("You must init first");

        }

        // 解密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.DECRYPT_MODE, mKp.getPrivate());
//        byte[] decode = Base64.decode(encrypted, Base64.DEFAULT);

        byte[] arr = cp.doFinal(encrypted);
        return arr;
    }




    /**
     * 使用私钥进行解密
     */
    public static byte[] encryptByPublicKey(byte[] encrypted) throws Exception {


        if (ALIAS == null) {
            throw new RuntimeException("You must init first");

        }

        // 解密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.ENCRYPT_MODE, mKp.getPublic());

        byte[] arr = cp.doFinal(encrypted);
        return arr;
    }


    private static void logThis(String msg) {
        if (mLogEnable) {
            Log.e(TAG, "--------------------------------------------------\n");
            Log.d(TAG, msg);
            Log.e(TAG, "--------------------------------------------------");
        }
    }


}
