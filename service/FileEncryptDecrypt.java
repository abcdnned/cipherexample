package cn.insightcredit.cloud.app.loan.common.baidukeys.service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import cn.insightcredit.cloud.app.loan.common.baidukeys.common.util.Security;
import cn.insightcredit.cloud.app.loan.common.baidukeys.service.decryption.DecryptParam;
import cn.insightcredit.cloud.app.loan.common.baidukeys.service.decryption.DecryptResult;
import cn.insightcredit.cloud.app.loan.common.baidukeys.service.encryption.EncryptParam;
import cn.insightcredit.cloud.app.loan.common.baidukeys.service.encryption.EncryptResult;

/**
 * 解密文件服务（算法A）
 * <p>
 * Created by wangjiannan on 2017/10/13.
 */
public class FileEncryptDecrypt {

    public static final int KEY_GEN_INIT = 128;
    public static final int IV_RANDOM_INIT_SIZE = 16;
    public static final String KEY_FILE_DEFAULT_NAME = "key";

    public DecryptResult decryptFile(DecryptParam param) {

        // 1. 初始化
        DecryptResult result = new DecryptResult();
        preHandleDecrypt(param);

        // 2. 获取要解密的文件
        String[] fileNames = Security.getSortedFiles(param.getEncryptDir(),
                param.getFileSuffix());

        // 3. 获取公钥私钥
        KeyFactory keyFactory = Security.getRSAKeyFactory();
        PublicKey publicKeyPartner = Security.getX509EncodedKeySpec(keyFactory, param.getPublicKeyPartner());
        PrivateKey privateKeyLocal = Security.getPKCS8EncodedKeySpec(keyFactory, param.getPrivateKeyLocal());

        // 4. 验签
        if (!verify(param, fileNames, publicKeyPartner)) {
            result.setFailFlow("验签");
            result.setFailReason("验签结果不一致");
            return result;
        }

        // 5. key&iv解密
        SecretKeySpec aesKey2 = null;
        byte[] iv2 = new byte[0];
        try {
            String decryptKey = Security.decryptRSA(privateKeyLocal, param.getKey());
            String decryptIv = Security.decryptRSA(privateKeyLocal, param.getIv());
            // 解密
            aesKey2 = new SecretKeySpec(Base64.decodeBase64(decryptKey), Security.AES);
            iv2 = Base64.decodeBase64(decryptIv);
        } catch (Exception e) {
            throw new EncryptDecryptException(e, e.getMessage(), "key&iv解密");
        }

        // 6. 解密文件
        try {
            Security.decryptfile(aesKey2, new IvParameterSpec(iv2),
                    param.getEncryptDir(), param.getDecryptDir(), fileNames);
        } catch (Exception e) {
            throw new EncryptDecryptException(e, e.getMessage(), "解密文件");
        }
        return result;
    }

    public boolean verify(DecryptParam param, String[] fileNames, PublicKey publicKey) {

        // 1. 拼接摘要
        String md = param.getKey() + param.getIv();
        try {
            for (String name : fileNames) {
                md += Security.sha256file(param.getEncryptDir() + File.separator + name);
            }
        } catch (Exception e) {
            throw new EncryptDecryptException(e, e.getMessage(), "摘要");
        }

        // 2. 验签
        boolean flag = false;
        try {
            flag = Security.verify(publicKey, md, param.getSign());
        } catch (Exception e) {
            throw new EncryptDecryptException(e, e.getMessage(), "验签");
        }

        return flag;

    }

    public void preHanleEncrypt(EncryptParam param) {
        // 1.1. 检查原文件目录是否存在
        Security.checkDecryptDir(param.getSourceDir());

        // 1.2. 初始化加密文件路径
        Security.initFileDir(param.getTargetDir());

        // 1.4. key文件名称
        if (StringUtils.isEmpty(param.getKeyFileName())) {
            param.setKeyFileName(KEY_FILE_DEFAULT_NAME);
        }

    }

    public void preHandleDecrypt(DecryptParam param) {
        if (param.isNeedUnTar()) {
            Security.doUnTarGZip(param.getEncryptDir(),
                    param.getEncryptDir(), param.getTarFileName());
        }
        // 读取KEY文件内容
        if (param.isNeedReadKEYFile()) {
            readKEYFile(param);
        }
        // 检查解密文件目录是否存在,不存在则创建该目录
        Security.initFileDir(param.getDecryptDir());
    }

    private DecryptParam readKEYFile(DecryptParam param) {
        try {
            List<String> lines = FileUtils.readLines(new File(
                            param.getEncryptDir() + File.separator + param.getKeyFileName()),
                    Charset.forName(Security.CHARSET));
            if (lines.size() > 0) {
                param.setKey(lines.get(0));
            }
            if (lines.size() > 1) {
                param.setIv(lines.get(1));
            }
            if (lines.size() > 2) {
                param.setSign(lines.get(2));
            }
        } catch (IOException e) {
            throw new EncryptDecryptException(e, "读KEY文件异常", "KEY文件处理");
        } catch (IndexOutOfBoundsException e) {
            throw new EncryptDecryptException(e, "读取KEY文件指定行异常，读取行数超过实际最大行数", "KEY文件处理");
        }
        return param;
    }

    public EncryptResult encryptFile(EncryptParam param) {
        EncryptResult result = new EncryptResult();

        // 1. 初始化
        preHanleEncrypt(param);
        // 初始化公钥私钥
        KeyFactory keyFactory = Security.getRSAKeyFactory();
        PublicKey publicKeyPartner = Security.getX509EncodedKeySpec(keyFactory, param.getPublicKeyPartner());
        PrivateKey privateKeyLocal = Security.getPKCS8EncodedKeySpec(keyFactory, param.getPrivateKeyLocal());

        // 2. 随机创建AES的key和iv, 必须随机
        // 2.1. 创建AES的key
        KeyGenerator keyGen = Security.getAESKeyGenerator();
        keyGen.init(KEY_GEN_INIT); // 暂定128
        SecretKey secretKey = keyGen.generateKey();
        SecretKeySpec aesKey = new SecretKeySpec(secretKey.getEncoded(), Security.AES);
        String key = Base64.encodeBase64String(secretKey.getEncoded());
        // 2.2. 创建IV
        SecureRandom r = new SecureRandom();
        byte[] iv = new byte[IV_RANDOM_INIT_SIZE];
        r.nextBytes(iv);
        String ivParam = Base64.encodeBase64String(iv);

        // 3. 加密文件
        String[] fileNames = Security
                .encryptFiles(aesKey, new IvParameterSpec(iv),
                        param.getSourceDir(), param.getTargetDir(), param.getTargetFileSuffix());
        // 加密的key
        String encryptKey = Security.encryptRSA(publicKeyPartner, key);
        // 加密的iv
        String encryptIvParam = Security.encryptRSA(publicKeyPartner, ivParam);

        // 4. 签名
        String md = encryptKey + encryptIvParam;
        for (String name : fileNames) {
            // 计算每个文件的sha256
            String sha256file = Security.sha256file(param.getTargetDir() + File.separator + name);
            ;
            md += sha256file;
        }
        String sign = Security.sign(privateKeyLocal, md);

        // 5. 创建key文件
        Security.createKeyFile(param.getTargetDir(), param.getKeyFileName(), encryptKey, encryptIvParam, sign);

        if (param.isNeedTar()) {

            // 6. 打包
            Security.doTarGZip(param.getTargetDir(), param.getKeyFileName(), fileNames, param.getTarFileName());

            // 7. 生成md5文件
            Security.geneMd5(param.getTargetDir(), param.getTarFileName());
        }

        return result;
    }
}
