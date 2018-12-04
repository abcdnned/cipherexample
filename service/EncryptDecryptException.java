package cn.insightcredit.cloud.app.loan.common.baidukeys.service;

/**
 * 加解密处理异常
 * <p>
 * Created by wangjiannan on 2017/10/18.
 */
public class EncryptDecryptException extends RuntimeException {

    private String failReason;
    private String failFlow;

    public EncryptDecryptException(Throwable cause, String failReason, String failFlow) {
        super(cause);
        this.failReason = failReason;
        this.failFlow = failFlow;
    }

    public String getFailReason() {
        return failReason;
    }

    public void setFailReason(String failReason) {
        this.failReason = failReason;
    }

    public String getFailFlow() {
        return failFlow;
    }

    public void setFailFlow(String failFlow) {
        this.failFlow = failFlow;
    }
}
