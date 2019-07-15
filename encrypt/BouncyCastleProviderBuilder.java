package cn.cccb.appsource.jd.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author red
 * @date 2018/6/25.
 */
public class BouncyCastleProviderBuilder {
    private static BouncyCastleProvider bcProvider = new BouncyCastleProvider();

    public static BouncyCastleProvider build() {
        return  bcProvider;
    }
}
