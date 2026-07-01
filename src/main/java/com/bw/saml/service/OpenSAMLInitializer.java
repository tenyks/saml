package com.bw.saml.service;

import org.opensaml.core.config.InitializationService;
//import org.opensaml.xmlsec.config.XMLSecurityInitializer;

/**
 *
 *
 * @author v-lizy81
 * @version 1.0.0
 * @date 2026/6/30
 * @since 0.1.0
 */
public class OpenSAMLInitializer {
    private static volatile boolean initialized = false;

    public static synchronized void initialize() throws Exception {
        if (initialized) {
            return;
        }
        // OpenSAML 4.x 标准初始化
//        InitializationService.initialize();
        // 初始化 XML 安全组件（签名/加密）
//        new XMLSecurityInitializer().init();
        initialized = true;
    }
}
