package cn.insightcredit.cloud.app.loan.common.baidukeys.service.encryption;

import cn.insightcredit.cloud.app.loan.common.baidukeys.service.BaseParam;

;

/**
 * 加密文件服务参数
 * <p>
 * Created by wangjiannan
 */
public class EncryptParam extends BaseParam {

    private String sourceDir;
    private String targetDir;
    private String targetFileSuffix;

    public String getSourceDir() {
        return sourceDir;
    }

    public void setSourceDir(String sourceDir) {
        this.sourceDir = sourceDir;
    }

    public String getTargetDir() {
        return targetDir;
    }

    public void setTargetDir(String targetDir) {
        this.targetDir = targetDir;
    }

    public String getTargetFileSuffix() {
        return targetFileSuffix;
    }

    public void setTargetFileSuffix(String targetFileSuffix) {
        this.targetFileSuffix = targetFileSuffix;
    }

}
