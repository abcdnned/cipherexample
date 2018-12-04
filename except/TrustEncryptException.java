package cn.insightcredit.cloud.app.loan.common.baidukeys.except;

import cn.insightcredit.cloud.app.loan.common.baidukeys.constant.TrustEncryptFileRespEnum;

/**
 * Created by zhanglei59 on 2018/1/3.
 */
public class TrustEncryptException extends RuntimeException {

    private int status;

    private String description;

    public TrustEncryptException(String description, Throwable cause, int status) {
        super(cause);
        this.description = description;
        this.status = status;
    }

    public TrustEncryptException(TrustEncryptFileRespEnum respEnum) {
        super();
        this.description = respEnum.getMessage();
        this.status = respEnum.getType();
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
