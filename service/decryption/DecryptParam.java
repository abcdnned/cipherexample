package cn.insightcredit.cloud.app.loan.common.baidukeys.service.decryption;

import cn.insightcredit.cloud.app.loan.common.baidukeys.service.BaseParam;

/**
 * 解密参数
 * <p>
 * Created by wangjiannan on 2017/10/13.
 */
public class DecryptParam extends BaseParam {

    private String encryptDir;
    private String decryptDir;
    private String fileSuffix;

    private boolean needReadKEYFile;
    private String key;
    private String iv;
    private String sign;

    /**
     * 加密文件目录
     */
    public String getEncryptDir() {
        return encryptDir;
    }

    /**
     * 加密文件目录
     */
    public void setEncryptDir(String encryptDir) {
        this.encryptDir = encryptDir;
    }

    /**
     * 解密文件目录
     */
    public String getDecryptDir() {
        return decryptDir;
    }

    /**
     * 解密文件目录
     */
    public void setDecryptDir(String decryptDir) {
        this.decryptDir = decryptDir;
    }

    /**
     * 是否需要读取KEY文件，如果需要，则key,iv,sign从KEY文件中取得
     */
    public boolean isNeedReadKEYFile() {
        return needReadKEYFile;
    }

    /**
     * 是否需要读取KEY文件，如果需要，则key,iv,sign从KEY文件中取得
     */
    public void setNeedReadKEYFile(boolean needReadKEYFile) {
        this.needReadKEYFile = needReadKEYFile;
    }

    public String getFileSuffix() {
        return fileSuffix;
    }

    public void setFileSuffix(String fileSuffix) {
        this.fileSuffix = fileSuffix;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getSign() {
        return sign;
    }

    public void setSign(String sign) {
        this.sign = sign;
    }
}
