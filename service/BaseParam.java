package cn.insightcredit.cloud.app.loan.common.baidukeys.service;

import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * 加解密基础参数
 * <p>
 * Created by wangjiannan on 2017/10/13.
 */
public class BaseParam {

    private String privateKeyLocal;
    private String publicKeyPartner;

    private String tarFileName;
    private boolean needUnTar;
    private boolean needTar;

    private String keyFileName;

    private boolean delMidFile = false;  // 是否删除中间文件

    public boolean isDelMidFile() {
        return delMidFile;
    }

    public BaseParam setDelMidFile(boolean delMidFile) {
        this.delMidFile = delMidFile;
        return this;
    }

    public String getPrivateKeyLocal() {
        return privateKeyLocal;
    }

    public void setPrivateKeyLocal(String privateKeyLocal) {
        this.privateKeyLocal = privateKeyLocal;
    }

    public String getPublicKeyPartner() {
        return publicKeyPartner;
    }

    public void setPublicKeyPartner(String publicKeyPartner) {
        this.publicKeyPartner = publicKeyPartner;
    }

    public String getTarFileName() {
        return tarFileName;
    }

    public void setTarFileName(String tarFileName) {
        this.tarFileName = tarFileName;
    }

    public boolean isNeedTar() {
        return needTar;
    }

    public void setNeedTar(boolean needTar) {
        this.needTar = needTar;
    }

    public boolean isNeedUnTar() {
        return needUnTar;
    }

    public void setNeedUnTar(boolean needUnTar) {
        this.needUnTar = needUnTar;
    }

    public String getKeyFileName() {
        return keyFileName;
    }

    public void setKeyFileName(String keyFileName) {
        this.keyFileName = keyFileName;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
