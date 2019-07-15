package cn.cccb.appsource.jd.util;

import java.security.SecureRandom;

/**
 * @author red
 * @date 2018/6/13.
 */
public class AlgorithmUtil {

    public static String getAESRandomKey() {
        SecureRandom random = new SecureRandom();
        long randomKey = random.nextLong();
        return String.valueOf(randomKey);
    }

    public static String encryptWithRSA(String data, String key) throws Exception {
        return RSAUtil.encryptByPublicKey(data, key);
    }

    public static String encryptWithAES(String data, String key) throws Exception {
        return AESUtil.encryptWithBC(data, key);
    }

    public static String decryptWithRSA(String data, String key) throws Exception {
        return new String(RSAUtil.decryptByPrivateKey(data, key), "utf-8");
    }

    public static String decryptWithAES(String data, String key) throws Exception {
        return AESUtil.decryptWithBC(data, key);
    }

    public static String sign(String data, String key) throws Exception {
        return RSAUtil.sign(data.getBytes(), key);
    }

    public static boolean verify(String data, String key, String signData) throws Exception {
        return RSAUtil.verify(data.getBytes(), key, signData);
    }

}
