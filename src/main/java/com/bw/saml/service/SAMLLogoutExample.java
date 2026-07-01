package com.bw.saml.service;

import org.opensaml.saml.saml2.core.LogoutRequest;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 *
 *
 * @author v-lizy81
 * @version 1.0.0
 * @date 2026/6/30
 * @since 0.1.0
 */
public class SAMLLogoutExample {

    public static void main(String[] args) throws Exception {
        // 1. 初始化 OpenSAML
        OpenSAMLInitializer.initialize();

        // 2. 加载私钥（PKCS#8 格式）
        byte[] keyBytes = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALQ9wsikZsu2mkzngQg4kGqhkLvfcBAB6m3F7u/2ZDWBpW/RyBjOIGua50Kq2SEftZ43LLNQfumoEZkRLtw2/Uii+jqrHShGPCmV99fFYZLKBAitZhb87sCv0u1QBwGstwKS3wTAgvvLGe547wcqkqNAgBQHEL7uZrZGDwuscx19AgMBAAECgYBX9SPPIlt/4laeXQNc7a2cO8gTxtA7H5Q1ibg2pjj025XOYcOSR1UO7gMZR6K6RW0uDqLjxs6IXBpqZjZGBRfIu80x9DbZCzmZCGjb0p46ZQ5g+DKeU8++/ClqgOi/5v/a4CuU29ReNV5oBoJvmCJ+QDw0J7XuLer5KHW+yzCRSQJBAP/7OdfEgOKdioEOqQOnhyxBiRZzRH/iplEOtT6VVJB34YdJ/qECfgiGCd33IDpg3b2DuZ+3IPz6ZHdn9QbJq18CQQC0QR9T1AJaCoUhivfBBZ2j3ndGvyguZPqHbRe6M3FVsFiEKIXMsYrjujkwiWxSGtPZkyejzKR98OGrL3281QCjAkEA3yH3hsyEaIVZISxNSaEzo/EwdUBe+nbv8QI4HOiAgTnufkaSzXjlsbpdSX3MOvcK8tKq8Lzp5XrCLo+Qt6z9UwJACOJExv7l9sYZ9aNBvrOmJ1NpkYUOV+sGJfKMftLWPSDp2+mbXpFJhRvCgc/kFM/ZrRmBlKMbYFGk7ajzi4D7/QJBANRkQgTfnfS9jlgjWHeY6K6g7OvelrgvQ0QwndGpfYz8uh3NsJTVV9p5mxjrWap+sj5bQeWn071RfJW2P0fs48s=".getBytes();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);

        // 3. 创建 Logout 服务
        SAMLLogoutService logoutService = new SAMLLogoutService(
                "http://MyLinuxPC:48080/idp/logout",          // SP 实体 ID
                "https://auth.air.gdrising.com.cn/mounisso/v1/cas/logout",        // IDP 单点登出端点
                privateKey
        );

        // 4. 构建 LogoutRequest
        LogoutRequest logoutRequest = logoutService.buildLogoutRequest(
                "lizhongyun",                    // NameID 值
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                "session-index-from-login"             // SessionIndex
        );

        // 5. 签名（可选，但生产环境强烈建议）
        logoutService.signLogoutRequest(logoutRequest);

        // 6. 打印调试信息
        System.out.println("LogoutRequest XML:");
        System.out.println(logoutService.marshallToString(logoutRequest));

        // 7. 发送 LogoutRequest
        // 注意：实际场景中，应返回重定向 URL 给前端，由用户浏览器发起
        // 此处仅演示
        String result = logoutService.sendLogoutRequest(logoutRequest, null);
        System.out.println("Result: " + result);

        // 8. 处理 LogoutResponse（在接收端）
//        SAMLLogoutResponseProcessor processor = new SAMLLogoutResponseProcessor();
        // 假设从请求参数中获取 SAMLResponse
        // LogoutResponse response = processor.parseLogoutResponse(samlResponseParam);
        // if (processor.isLogoutSuccess(response)) {
        //     // 清理本地 Session
        //     request.getSession().invalidate();
        // }
    }
}
