package cn.cccb.appsource.jd.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.Security;

/**
 * @author red
 * @date 2018/6/13.
 */
public class AESUtil {
    /**
     * 加密方式
     */
    public static final String KEY_ALGORITHM = "AES";
    /**
     * 安全随机签名算法
     */
    public static final String SECURE_ALGORITHM = "SHA1PRNG";
    /**
     * 加密算法
     */
    public static final String SECRYPT_ALGORITHM = "AES/ECB/PKCS5Padding";

    /**
     * 报文加密
     * @param randomKey 随机密钥
     * @param plainData 上送报文
     * @return 报文密文
     * @throws Exception
     */
    public static String encrypt(String plainData, String randomKey) throws Exception {
        KeyGenerator aesGen = KeyGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom secureRandom = SecureRandom.getInstance(SECURE_ALGORITHM);
        secureRandom.setSeed(randomKey.getBytes());
        aesGen.init(128, secureRandom);

        SecretKey secretKey = aesGen.generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM);
        Security.addProvider(BouncyCastleProviderBuilder.build());
        Cipher aesCipher = Cipher.getInstance(SECRYPT_ALGORITHM, "BC");
        aesCipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] aesData = aesCipher.doFinal(plainData.getBytes("utf-8"));
        return Base64.encodeBase64String(aesData);
    }

    public static String encryptWithBC(String data, String key) throws Exception {

        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.put(key.getBytes());
        KeyParameter kp = new KeyParameter(buffer.array());
        byte[] bytes = data.getBytes("UTF8");

        CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(aes, new PKCS7Padding());
        cipher.init(true, kp);

        byte[] output = new byte[cipher.getOutputSize(bytes.length)];
        int len = cipher.processBytes(bytes, 0, bytes.length, output, 0);
        cipher.doFinal(output, len);

        return Base64.encodeBase64String(output);
    }

    public static String decryptWithBC(String data, String key) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.put(key.getBytes());
        KeyParameter kp = new KeyParameter(buffer.array());

        byte[] bytes = Base64.decodeBase64(data);

        CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(aes, new PKCS7Padding());
        cipher.init(false, kp);

        byte[] output = new byte[cipher.getOutputSize(bytes.length)];
        int len = cipher.processBytes(bytes, 0, bytes.length, output, 0);
        int len2 = cipher.doFinal(output, len);
        byte rawData[] = new byte[len+len2];
        System.arraycopy(output, 0, rawData, 0, rawData.length);
        String plainData = new String(rawData, Charset.forName("utf-8"));
        return plainData;
    }

    /**
     * 报文解密
     * @param aesBase64
     * @param randomKey
     * @return
     * @throws Exception
     */
    public static String decrypt(String aesBase64, String randomKey) throws Exception {
        byte[] aesData = Base64.decodeBase64(aesBase64);
        KeyGenerator aesGen = KeyGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom secureRandom = SecureRandom.getInstance(SECURE_ALGORITHM);
        secureRandom.setSeed(randomKey.getBytes());
        aesGen.init(128, secureRandom);
        SecretKey secretKey = aesGen.generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM);
        Security.addProvider(BouncyCastleProviderBuilder.build());
        Cipher aesCipher = Cipher.getInstance(SECRYPT_ALGORITHM, "BC");
        aesCipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] plain = aesCipher.doFinal(aesData);
        String plainData = new String(plain, Charset.forName("utf-8"));
        return plainData;
    }

    /**
     * 生成随机密钥，一次一密
     * @return
     */
    public static String getRandomKey() {
        SecureRandom random = new SecureRandom();
        long randomKey = random.nextLong();
        return String.valueOf(randomKey);
    }
}