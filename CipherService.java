package cn.insightcredit.cloud.app.loan.common.baidukeys;

import java.util.TreeMap;

import cn.insightcredit.cloud.app.loan.common.baidukeys.bean.EncryptBean;
import cn.insightcredit.cloud.app.loan.common.baidukeys.common.util.Security;
import cn.insightcredit.cloud.app.loan.common.baidukeys.service.FileEncryptDecrypt;
import cn.insightcredit.cloud.app.loan.common.baidukeys.service.decryption.DecryptParam;
import cn.insightcredit.cloud.app.loan.common.baidukeys.service.encryption.EncryptParam;


/**
 * Created by zhanglei59 on 2017/11/28.
 */

public class CipherService {

    private static final FileEncryptDecrypt fileEncryptDecrypt = new FileEncryptDecrypt();

    private static EncryptBean doEncrypt(String data,
                                         String publicKey, String iCode) throws Exception {

        String aesKeyWithBase64 = Security.generateKey();
        String aesIVWithBase64 = Security.generateIv();
        String key = Security.encryptRSA(aesKeyWithBase64, publicKey);
        String salt = Security.encryptRSA(aesIVWithBase64, publicKey);
        String cipherData;
        cipherData = Security.encryptAES(data, aesKeyWithBase64, aesIVWithBase64);
        EncryptBean bean = new EncryptBean();
        bean.setData(cipherData);
        bean.setKey(key);
        bean.setSalt(salt);
        bean.setIcode(iCode);
        return bean;
    }

    public static EncryptBean encryptData(String data, String publicKey, String privateKey,
                                          String iCode) throws Exception {
        EncryptBean bean = doEncrypt(data, publicKey, iCode);
        String sign = Security.requestSign(new TreeMap<String, String>(bean.toMap()), privateKey);
        bean.setSign(sign);
        return bean;
    }

    public static String decryptData(String data, String key, String salt, String privateKey) throws Exception {

        String decryptData = null;

        String aesKey = Security.decryptRSA(key, privateKey);
        String aesSalt = Security.decryptRSA(salt, privateKey);
        decryptData = Security.decryptAES(data, aesKey, aesSalt);

        return decryptData;
    }

    public static boolean checkSign(TreeMap<String, String> map, String publicKey, String sign)
            throws Exception {
        map.remove("sign");
        // 机构公钥验签

        boolean checkPass = Security.responseCheckSign(map, sign, publicKey);

        return checkPass;
    }

    public static void decryptFileData(DecryptParam decryptParam) {

//        DecryptResult result = fileEncryptDecrypt.decryptFile(decryptParam);
//        if (result != null && !result.isSucc()) {
//            TrustEncryptFileRespEnum respEnum = TrustEncryptFileRespEnum.DECRYPT_FILE_EXCEPTION;
//            throw new TrustEncryptException(respEnum.getMessage(), result.getCause(), respEnum.getType());
//        }

    }

    public static void encryptFileData(EncryptParam encryptParam) throws Exception {

//        EncryptResult result = fileEncryptDecrypt.encryptFile(encryptParam);
//        if (result != null && !result.isSucc()) {
//            TrustEncryptFileRespEnum respEnum = TrustEncryptFileRespEnum.ENCRYPT_FILE_EXCEPTION;
//            throw new TrustEncryptException(respEnum.getMessage(), result.getCause(), respEnum.getType());
//        }

    }

}
