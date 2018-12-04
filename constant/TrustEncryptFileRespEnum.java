package cn.insightcredit.cloud.app.loan.common.baidukeys.constant;

/**
 * Created by zhanglei59 on 2018/1/3.
 */
public enum TrustEncryptFileRespEnum {

    ENCRYPT_FILE_EXCEPTION(11, "加密异常"),
    DECRYPT_FILE_EXCEPTION(12, "解密异常");

    private int code;

    private String message;

    TrustEncryptFileRespEnum(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public Integer getType() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
