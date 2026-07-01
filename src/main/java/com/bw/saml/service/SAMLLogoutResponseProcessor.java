package com.bw.saml.service;

import org.apache.commons.codec.binary.Base64;
import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 *
 *
 * @author v-lizy81
 * @version 1.0.0
 * @date 2026/6/30
 * @since 0.1.0
 */
public class SAMLLogoutResponseProcessor {
    /**
     * 解析 HTTP-Redirect 绑定中的 LogoutResponse
     *
     * @param samlResponseParam URL 参数 SAMLResponse 的值（Base64 编码、Deflate 压缩）
     */
    public LogoutResponse parseLogoutResponse(String samlResponseParam) throws Exception {
        // 1. Base64 解码
        byte[] decoded = Base64.decodeBase64(samlResponseParam);

        // 2. Inflate 解压
        ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
        InflaterInputStream iis = new InflaterInputStream(bais, new Inflater(true));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = iis.read(buffer)) > 0) {
            baos.write(buffer, 0, len);
        }
        byte[] inflated = baos.toByteArray();

        // 3. 解析 XML
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document document = db.parse(new ByteArrayInputStream(inflated));
        Element rootElement = document.getDocumentElement();

        // 4. 使用 OpenSAML 反序列化
        UnmarshallerFactory unmarshallerFactory =
                XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(rootElement);
        XMLObject xmlObject = unmarshaller.unmarshall(rootElement);

        if (xmlObject instanceof LogoutResponse) {
            return (LogoutResponse) xmlObject;
        }
        throw new IllegalArgumentException("Not a LogoutResponse");
    }

    /**
     * 检查登出是否成功
     */
    public boolean isLogoutSuccess(LogoutResponse response) {
        Status status = response.getStatus();
        if (status == null) {
            return false;
        }
        StatusCode statusCode = status.getStatusCode();
        if (statusCode == null) {
            return false;
        }
        return StatusCode.SUCCESS.equals(statusCode.getValue());
    }

    /**
     * 获取错误信息
     */
    public String getStatusMessage(LogoutResponse response) {
        Status status = response.getStatus();
        if (status == null || status.getStatusMessage() == null) {
            return null;
        }
//        return status.getStatusMessage().getValue();
        return status.getStatusMessage().getMessage();
    }
}
