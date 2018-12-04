package cn.insightcredit.cloud.app.loan.common.baidukeys.bean;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

/**
 * 加密后文件
 */
public class EncryptBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private String sign;  // 签名
    private String data;  // 数据
    private String key; // key
    private String salt; // 盐头
    private String icode; // 机构码

    public EncryptBean(String sign, String data, String key, String salt, String icode) {
        this.sign = sign;
        this.data = data;
        this.key = key;
        this.salt = salt;
        this.icode = icode;
    }
    public EncryptBean() {
    }

    public String getSign() {
        return sign;
    }

    public EncryptBean setSign(String sign) {
        this.sign = sign;
        return this;
    }

    public String getData() {
        return data;
    }

    public EncryptBean setData(String data) {
        this.data = data;
        return this;
    }

    public String getKey() {
        return key;
    }

    public EncryptBean setKey(String key) {
        this.key = key;
        return this;
    }

    public String getSalt() {
        return salt;
    }

    public EncryptBean setSalt(String salt) {
        this.salt = salt;
        return this;
    }

    public String getIcode() {
        return icode;
    }

    public EncryptBean setIcode(String icode) {
        this.icode = icode;
        return this;
    }

    public Map<String, String> toMap() {
        Map<String, String> map = new HashMap<String, String>();
        setMapNotNull(map, "icode", icode);
        setMapNotNull(map, "data", data);
        setMapNotNull(map, "key", key);
        setMapNotNull(map, "salt", salt);
        setMapNotNull(map, "sign", sign);
        return map;
    }

    // 如果不为空则设置值
    private void setMapNotNull(Map<String, String> map, String key, String value) {
        if (StringUtils.isNotBlank(value)) {
            map.put(key, value);
        }
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("EncryptBean{");
        sb.append("sign='").append(sign).append('\'');
        sb.append(", data='").append(data).append('\'');
        sb.append(", key='").append(key).append('\'');
        sb.append(", salt='").append(salt).append('\'');
        sb.append(", icode='").append(icode).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
