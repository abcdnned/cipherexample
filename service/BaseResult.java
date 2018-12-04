package cn.insightcredit.cloud.app.loan.common.baidukeys.service;

import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * 加解密基础返回实体
 * <p>
 * Created by wangjiannan on 2017/10/18.
 */
public class BaseResult {

    private Throwable cause;
    private boolean succ = true;
    private String failReason;
    private String failFlow;

    public Throwable getCause() {
        return cause;
    }

    public void setCause(Throwable cause) {
        setSucc(false);
        this.cause = cause;
    }

    public boolean isSucc() {
        return succ;
    }

    public void setSucc(boolean succ) {
        this.succ = succ;
    }

    public String getFailReason() {
        return failReason;
    }

    public void setFailReason(String failReason) {
        setSucc(false);
        this.failReason = failReason;
    }

    public String getFailFlow() {
        setSucc(false);
        return failFlow;
    }

    public void setFailFlow(String failFlow) {
        setSucc(false);
        this.failFlow = failFlow;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
