package cn.insightcredit.cloud.app.loan.common.baidukeys.common.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.DigestInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;

import cn.insightcredit.cloud.app.loan.common.baidukeys.service.EncryptDecryptException;


/**
 * 加密、解密工具
 * <p>
 * Created by baidu
 */
public class Security {

    public static final String SIGN_ALGORITHM = "SHA256withRSA";
    public static final String CHARSET = "UTF-8";
    public static final String AES_ALGORITHM_CFB_PKCS5 = "AES/CFB/PKCS5Padding";
    public static final String RSA_ALGORITHM_ECB_PKCS1 = "RSA/ECB/PKCS1Padding";
    public static final String RSA = "RSA";
    public static final String AES = "AES";
    /**
     * RSA密钥长度.
     */
    private static final int KEY_SIZE = 2048;
    private static final String EQUAL = "=";
    private static final String AND = "&";

    public static KeyFactory getRSAKeyFactory() {
        // 3. 获取公钥私钥
        try {
            return KeyFactory.getInstance(RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptDecryptException(e, "没有这个算法：" + RSA, "密钥初始化");
        }
    }

    public static KeyGenerator getAESKeyGenerator() {
        try {
            return KeyGenerator.getInstance(AES);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptDecryptException(e, "没有这个算法：" + AES, "密钥初始化");
        }
    }

    /**
     * 创建iv
     */
    public static String generateIv() {
        return Base64.encodeBase64String(RandomUtils.nextBytes(16));
    }

    public static String generateKey() throws Exception {

        KeyGenerator kgen = getAESKeyGenerator();

        // 最长可以是256,但是256需要jre更新一个文件才能支持.
        kgen.init(128);

        SecretKey skey = kgen.generateKey();

        return Base64.encodeBase64String(skey.getEncoded());
    }

    public static PublicKey getX509EncodedKeySpec(KeyFactory keyFactory, String key) {
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
                Base64.decodeBase64(key));
        PublicKey publicKey = null;
        try {
            publicKey = keyFactory.generatePublic(x509KeySpec);
        } catch (InvalidKeySpecException e) {
            throw new EncryptDecryptException(e, "公钥非法", "密钥初始化");
        }
        return publicKey;
    }

    public static PrivateKey getPKCS8EncodedKeySpec(KeyFactory keyFactory, String key) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                Base64.decodeBase64(key));
        PrivateKey privateKey = null;
        try {
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new EncryptDecryptException(e, "私钥非法", "密钥初始化");
        }
        return privateKey;
    }

    /**
     * 根据公钥和原始内容产生加密内容.
     */
    public static String encryptRSA(PublicKey key, String content) {

        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM_ECB_PKCS1);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.encodeBase64String(cipher.doFinal(content.getBytes(CHARSET)));
        } catch (Exception e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "根据公钥和原始内容产生加密内容.");
        }
    }

    /**
     * 用对方公钥加密AES密钥.
     * <p>
     *
     * @param content   明文.
     * @param publicKey 公钥, Base64编码
     *
     * @return 密文, Base64编码
     *
     * @throws Exception
     */
    public static String encryptRSA(final String content, final String publicKey) throws Exception {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
            PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM_ECB_PKCS1);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            return Base64.encodeBase64String(cipher.doFinal(content.getBytes(CHARSET)));
        } catch (Exception e) {
            throw new Exception("加密过程失败, EncryptContent = " + content, e);
        }
    }

    /**
     * 用我方私钥解密AES密钥.
     * <p>
     *
     * @param content    密文, Base64编码
     * @param privateKey 我方私钥, Base64编码
     *
     * @return 明文
     *
     * @throws Exception
     */
    public static String decryptRSA(final String content, final String privateKey) throws Exception {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM_ECB_PKCS1);
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            return new String(cipher.doFinal(Base64.decodeBase64(content)), CHARSET);
        } catch (Exception e) {
            throw new Exception("解密过程失败, EncodeContent = " + content, e);
        }
    }

    /**
     * 根据私钥和加密内容产生原始内容.
     */
    public static String decryptRSA(PrivateKey key, String content)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM_ECB_PKCS1);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.decodeBase64(content)), CHARSET);
    }

    /**
     * 计算一个文件的sha256摘要.
     */
    public static String sha256file(String fileName) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "计算文件sha256摘要");
        }
        DigestInputStream dis = null;
        try {
            dis = new DigestInputStream(new BufferedInputStream(new FileInputStream(fileName)), md);
        } catch (FileNotFoundException e) {
            throw new EncryptDecryptException(e,
                    "sha256file error, " + fileName + " file not found!",
                    "计算文件sha256摘要");
        }
        try {
            while (dis.read() != -1) {
                ;
            }
            dis.close();
        } catch (IOException e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "计算文件sha256摘要");
        }
        return Base64.encodeBase64String(md.digest());
    }

    /**
     * 根据AES的key和IV加密文件.
     */
    public static String[] encryptFiles(SecretKeySpec aesKey, IvParameterSpec iv, String decryptDir,
                                        String encryptDir, String targetFileSuffix) {

        // 筛选.csv文件并按照升序方式排序
        String[] sortedFiles = getSortedFiles(decryptDir, targetFileSuffix);

        // 遍历该文件夹下的所有文件
        for (String fileName : sortedFiles) {
            File inFile = new File(decryptDir + File.separator + fileName);
            File outFile = new File(encryptDir + File.separator + fileName);
            // 加密文件
            encryptFileAES(aesKey, inFile, outFile, iv);
        }
        return sortedFiles;
    }

    /**
     * 获取加密/解密文件
     */
    public static String[] getSortedFiles(String decryptDir, String targetFileSuffix) {
        File file = new File(decryptDir);
        String[] files = file.list();

        // 在noah上一任务起始时间一致, 分表数>机器数的情况下,不会出现文件为空的情况,
        // 如果出现没有文件的情况,需要具体核实下
        if (files == null) {
            return new String[0];
        }
        return filterAndSortFiles(files, targetFileSuffix);
    }

    /**
     * 根据公钥进行验签.
     */
    public static boolean verify(PublicKey key, String content, String sign) {
        try {
            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initVerify(key);
            signature.update(content.getBytes(CHARSET));
            return signature.verify(Base64.decodeBase64(sign));
        } catch (Exception e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "根据公钥进行验签.");
        }
    }

    /**
     * 打包加密的csv文件和key文件.
     */
    public static void doTarGZip(String encryptDir, String keyFileName, String[] fileNames, String tarFileName) {

        try {
            TarArchiveOutputStream tar = new TarArchiveOutputStream(
                    new GzipCompressorOutputStream(
                            new BufferedOutputStream(
                                    new FileOutputStream(new File(encryptDir + File.separator + tarFileName)))));
            // 加密文件打包
            for (String name : fileNames) {
                File file = new File(encryptDir + File.separator + name);
                TarArchiveEntry tarEntry = new TarArchiveEntry(name);
                tarEntry.setSize(file.length());
                tar.putArchiveEntry(tarEntry);
                InputStream in = new FileInputStream(file);
                copy(in, tar);
                in.close();
                tar.closeArchiveEntry();
            }
            // key打包
            File file = new File(encryptDir + File.separator + keyFileName);
            TarArchiveEntry tarEntry = new TarArchiveEntry(keyFileName);
            tarEntry.setSize(file.length());
            tar.putArchiveEntry(tarEntry);
            InputStream in = new FileInputStream(file);
            copy(in, tar);
            in.close();
            tar.closeArchiveEntry();
            tar.close();
        } catch (IOException e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "打包加密文件");
        }
    }

    /**
     * 打包加密的csv文件和key文件.
     */
    public static void doTarGZip(String encryptDir, String[] fileNames, String tarFileName) {

        TarArchiveOutputStream tar = null;
        try {
            tar = new TarArchiveOutputStream(
                    new GzipCompressorOutputStream(
                            new BufferedOutputStream(
                                    new FileOutputStream(new File(encryptDir + File.separator + tarFileName)))));
            // 加密文件打包
            for (String name : fileNames) {
                File file = new File(encryptDir + File.separator + name);
                TarArchiveEntry tarEntry = new TarArchiveEntry(name);
                tarEntry.setSize(file.length());
                tar.putArchiveEntry(tarEntry);
                InputStream in = new FileInputStream(file);
                copy(in, tar);
                in.close();
                tar.closeArchiveEntry();
            }
        } catch (IOException e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "打包加密文件");
        } finally {
            if (tar != null) {
                IOUtils.closeQuietly(tar);
            }
        }
    }

    /**
     * 解包加密的文件.
     */
    public static void doUnTarGZip(String encryptDir, String decryptDir, String tarFiles) {
        try {
            TarArchiveInputStream tar = new TarArchiveInputStream(
                    new GzipCompressorInputStream(
                            new BufferedInputStream(
                                    new FileInputStream(new File(encryptDir + File.separator + tarFiles)))));
            TarArchiveEntry entry;
            while ((entry = (TarArchiveEntry) tar.getNextEntry()) != null) {
                File file = new File(decryptDir + File.separator + entry.getName());
                int count;
                byte[] data = new byte[1024];
                OutputStream fos = new FileOutputStream(file);
                while ((count = tar.read(data, 0, 1024)) != -1) {
                    fos.write(data, 0, count);
                }
                fos.close();
            }
            tar.close();
        } catch (IOException e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "解包加密文件");
        }
    }

    /**
     * 文件拷贝
     */
    public static void copy(InputStream is, OutputStream os) {
        int i;
        byte[] b = new byte[1024];
        try {
            while ((i = is.read(b)) != -1) {
                os.write(b, 0, i);
            }
        } catch (IOException e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "文件拷贝");
        }
    }

    /**
     * 根据AES的key和IV, 加密文件.
     */
    public static void encryptFileAES(SecretKey key, File in, File out, IvParameterSpec iv) {

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(AES_ALGORITHM_CFB_PKCS5);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        } catch (Exception e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "根据AES的key和IV加密文件");
        }
        FileInputStream is = null;
        try {
            is = new FileInputStream(in);
        } catch (FileNotFoundException e) {
            throw new EncryptDecryptException(e,
                    "encryptFileAES error, " + in.getName() + " not found",
                    "根据AES的key和IV加密文件");
        }
        CipherOutputStream os = null;
        try {
            os = new CipherOutputStream(new FileOutputStream(out), cipher);
        } catch (FileNotFoundException e) {
            throw new EncryptDecryptException(e,
                    "encryptFileAES error, " + out.getName() + " not found",
                    "根据AES的key和IV加密文件");
        }
        copy(is, os);
        try {
            is.close();
            os.close();
        } catch (Exception e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "根据AES的key和IV加密文件");
        }
    }

    /**
     * 加密
     */
    public static String encryptAES(final String str, final String keyStr, final String iv) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM_CFB_PKCS5);
            cipher.init(Cipher.ENCRYPT_MODE, getKey(keyStr), getIv(iv));
            final byte[] encryptData = cipher.doFinal(str.getBytes(CHARSET));
            return Base64.encodeBase64String(encryptData);
        } catch (Exception e) {
            throw new RuntimeException("AES encrypt error", e);
        }
    }

    /**
     * 解密
     */
    public static String decryptAES(final String str, final String keyStr, final String iv) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM_CFB_PKCS5);

            cipher.init(Cipher.DECRYPT_MODE, getKey(keyStr), getIv(iv));
            final byte[] decryptData = cipher.doFinal(Base64.decodeBase64(str.getBytes(CHARSET)));
            return new String(decryptData, CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("AES decrypt error", e);
        }
    }

    /**
     * 接受外部机构请求时验证签名(使用公钥)
     */
    public static boolean responseCheckSign(TreeMap<String, String> paramsMap,
                                            final String sign,
                                            final String publicKey) {
        String str = null;
        try {
            str = map2str(paramsMap);
            System.out.println("map2str:" + str);
            return rsa256CheckContent(str, sign, publicKey);
        } catch (Exception e) {

            throw new RuntimeException(
                    " outside agencies response check sign error,str:{" + str
                            + "},sign:{"
                            + sign + "} ", e);
        }
    }

    /**
     * 用对方公钥publicKey进行验签.
     * <p>
     *
     * @param content   验签的内容
     * @param sign      签名
     * @param publicKey 对方公钥, Base64编码
     *
     * @return 签名结果
     */
    public static boolean rsa256CheckContent(final String content, final String sign, final String publicKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
            PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initVerify(pubKey);
            signature.update(content.getBytes(CHARSET));
            return signature.verify(Base64.decodeBase64(sign));
        } catch (Exception e) {
            throw new RuntimeException("验签失败, RSAcontent = " + content + ",sign=" + sign, e);
        }
    }

    /**
     * map转成string
     */
    private static String map2str(TreeMap<String, String> map) {

        List<String> values = new ArrayList<String>();
        for (String key : map.keySet()) {
            String value = key + EQUAL + map.get(key);
            values.add(value);
        }
        return StringUtils.join(values, AND);
    }

    /**
     * 给外部机构发送请求时签名(使用私钥)
     */
    public static String requestSign(final TreeMap<String, String> paramsMap, final String privateKey) {

        String str = null;

        try {
            str = map2str(paramsMap);

            return rsa256Sign(str, privateKey);

        } catch (Exception e) {

            throw new RuntimeException(
                    "request outside agencies sign error.str:{"
                            + str + "} ",
                    e);
        }
    }

    /**
     * 用我方私钥privateKey对内容content进行签名.
     * <p>
     *
     * @param content    待签名的内容
     * @param privateKey 我方私钥, 经过64编码
     *
     * @return 签名
     */
    public static String rsa256Sign(final String content, final String privateKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initSign(priKey);
            signature.update(content.getBytes(CHARSET));
            return Base64.encodeBase64String(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException("签名失败, RSAcontent = " + content, e);
        }
    }

    /**
     * string转IV对象
     */
    private static AlgorithmParameterSpec getIv(final String iv) {
        return new IvParameterSpec(Base64.decodeBase64(iv));
    }

    /**
     * string转key对象
     */
    private static Key getKey(final String keyStr) {
        return new SecretKeySpec(Base64.decodeBase64(keyStr.getBytes()), "AES");
    }

    /**
     * 根据私钥和数据内容产生签名, base64编码.
     */
    public static String sign(PrivateKey key, String content) {

        try {
            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initSign(key);
            signature.update(content.getBytes(CHARSET));
            return Base64.encodeBase64String(signature.sign());
        } catch (Exception e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "根据私钥和数据内容产生签名, base64编码");
        }
    }

    // 筛选.xxx文件并按照升序方式排序
    public static String[] filterAndSortFiles(String[] files, final String targetFileSuffix) {
        List<String> fileList = Arrays.asList(files);
        List<String> newFileList = new ArrayList<String>();
        for (String fileName : fileList) {
            if (fileName.endsWith(targetFileSuffix)) {
                newFileList.add(fileName);
            }
        }
        Collections.sort(newFileList, new Comparator<String>() {
            @Override
            public int compare(String a, String b) {
                return a.substring(0, a.length() - targetFileSuffix.length())
                        .compareTo(b.substring(0, b.length() - targetFileSuffix.length()));
            }
        });
        return newFileList.toArray(new String[0]);
    }

    /**
     * 文件从一个目录拷贝到另外一个目录
     */
    public static void copyFile(String encryptDir, String downloadDir, String tarFileName) {
        initFileDir(downloadDir);

        try {
            FileUtils.copyFileToDirectory(new File(encryptDir + File.separator + tarFileName),
                    new File(downloadDir));
        } catch (IOException e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "文件从一个目录拷贝到另外一个目录");
        }
    }

    /**
     * 文件目录, 如果不存在新建
     */
    public static void initFileDir(String fileDir) {
        File file = new File(fileDir);
        if (!file.exists()) {
            if (!file.mkdirs()) {
                throw new EncryptDecryptException(null,
                        fileDir + "创建失败",
                        "新建目录");
            }
        }
    }

    /**
     * 检查原文件目录是否存在
     */
    public static void checkDecryptDir(String sourceFileDir) {
        File file = new File(sourceFileDir);
        if (!file.exists()) {
            throw new EncryptDecryptException(null,
                    sourceFileDir + " source file not exists: ",
                    "检查原文件目录");
        }
    }

    /**
     * 解密文件
     */
    public static void decryptfile(SecretKeySpec aesKey2, IvParameterSpec iv,
                                   String encryptDir, String decryptDir, String[] fileNames) {

        for (String name : fileNames) {
            File inFile = new File(encryptDir + File.separator + name);
            File outFile = new File(decryptDir + File.separator + name);
            decryptFileAES(aesKey2, inFile, outFile, iv);
        }
    }

    /**
     * 根据AES的key和IV, 解密文件.
     */
    public static void decryptFileAES(SecretKey key, File in, File out, IvParameterSpec iv) {

        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM_CFB_PKCS5);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            CipherInputStream is = new CipherInputStream(new FileInputStream(in), cipher);
            FileOutputStream os = new FileOutputStream(out);
            copy(is, os);
            is.close();
            os.close();
        } catch (Exception e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "根据AES的key和IV, 解密文件.");
        }
    }

    /**
     * 创建key文件, 并将key, iv, sign按行写入.
     */
    public static void createKeyFile(String decryptDir, String keyFileName, String key, String iv, String sign) {
        File file = new File(decryptDir + File.separator + keyFileName);
        try {
            FileWriter fw = new FileWriter(file);
            fw.write(key);
            fw.write("\n");
            fw.write(iv);
            fw.write("\n");
            fw.write(sign);
            fw.close();
        } catch (IOException e) {
            throw new EncryptDecryptException(e,
                    e.getMessage(),
                    "创建key文件, 并将key, iv, sign按行写入");
        }
    }

    /**
     * 打包后的文件生成md5文件
     */
    public static void geneMd5(String encryptDir, String tarFileName) {

        File tarFile = new File(encryptDir + File.separator + tarFileName);
        if (!tarFile.exists()) {
            return;
        }

        try {
            String md5Value = generateMD5(tarFile);

            File md5File = new File(encryptDir + File.separator + tarFileName.split("\\.")[0] + ".md5");

            FileUtils.write(md5File, md5Value, "UTF-8");
        } catch (Exception e) {
            throw new EncryptDecryptException(e,
                    "SecurityUtil generate md5 file error!",
                    "检查原文件目录");
        }
    }

    public static String generateMD5(File f) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("md5");
        FileInputStream fin = null;

        try {
            fin = new FileInputStream(f);
            long remainSize = f.length();
            long position = 0L;

            do {
                MappedByteBuffer byteBuffer = fin.getChannel().map(
                        FileChannel.MapMode.READ_ONLY, position, remainSize > 134217728L ? 134217728L : remainSize);
                md5.update(byteBuffer);
                remainSize -= 134217728L;
                position += 134217728L;
            } while (remainSize > 0L);

            String var11 = Hex.encodeHexString(md5.digest());
            return var11;
        } finally {
            IOUtils.closeQuietly(fin);
        }
    }

    /**
     * 生成公钥私钥
     */
    public static Map<KEY, String> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<KEY, String> map = new HashMap<KEY, String>();
        map.put(KEY.PUBLICKEY, Base64.encodeBase64String(rsaPublicKey.getEncoded()));
        map.put(KEY.PRIVATEKEY, Base64.encodeBase64String(rsaPrivateKey.getEncoded()));

        return map;
    }

    public enum KEY {
        /**
         * 公钥
         */
        PUBLICKEY,
        /**
         * 私钥
         */
        PRIVATEKEY
    }

}
