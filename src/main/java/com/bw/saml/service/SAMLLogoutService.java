package com.bw.saml.service;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 *
 *
 * @author v-lizy81
 * @version 1.0.0
 * @date 2026/6/30
 * @since 0.1.0
 */
public class SAMLLogoutService {
    private final XMLObjectBuilderFactory builderFactory;
    private final String spEntityId;
    private final String idpSingleLogoutUrl;
    private final Credential signingCredential;

    public SAMLLogoutService(String spEntityId,
                             String idpSingleLogoutUrl,
                             PrivateKey privateKey) {
        this.builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        this.spEntityId = spEntityId;
        this.idpSingleLogoutUrl = idpSingleLogoutUrl;
        // 将 PrivateKey 包装为 OpenSAML Credential
        this.signingCredential = CredentialSupport.getSimpleCredential((PublicKey) null, privateKey);
    }

    /**
     * 构建 LogoutRequest
     */
    public LogoutRequest buildLogoutRequest(String nameIdValue,
                                            String nameIdFormat,
                                            String sessionIndex) {
        // 1. 创建 LogoutRequest
        LogoutRequest logoutRequest = (LogoutRequest) builderFactory
                .getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME)
                .buildObject(LogoutRequest.DEFAULT_ELEMENT_NAME);

        // 2. 设置基本属性
        logoutRequest.setID("_" + System.currentTimeMillis());
        logoutRequest.setVersion(SAMLVersion.VERSION_20);
        logoutRequest.setIssueInstant(new DateTime());
        logoutRequest.setDestination(idpSingleLogoutUrl);

        // 3. 设置 Issuer（SP 实体 ID）
        Issuer issuer = (Issuer) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME)
                .buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(spEntityId);
        logoutRequest.setIssuer(issuer);

        // 4. 设置 NameID（当前登录用户的标识）
        NameID nameId = (NameID) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME)
                .buildObject(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(nameIdValue);
        nameId.setFormat(nameIdFormat != null ? nameIdFormat : NameID.TRANSIENT);
        logoutRequest.setNameID(nameId);

        // 5. 设置 SessionIndex（关键：关联到当前会话）
        SessionIndex sessionIndexElement = (SessionIndex) builderFactory
                .getBuilder(SessionIndex.DEFAULT_ELEMENT_NAME)
                .buildObject(SessionIndex.DEFAULT_ELEMENT_NAME);
//        sessionIndexElement.setValue(sessionIndex);
        sessionIndexElement.setSessionIndex(sessionIndex);
        logoutRequest.getSessionIndexes().add(sessionIndexElement);

        return logoutRequest;
    }

    /**
     * 对 LogoutRequest 进行签名
     */
    public void signLogoutRequest(LogoutRequest logoutRequest) throws Exception {
        Signature signature = (Signature) builderFactory
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        logoutRequest.setSignature(signature);

        // 执行签名
        Signer.signObject(signature);
    }

    /**
     * 将 SAML 对象序列化为字符串（用于调试）
     */
    public String marshallToString(SAMLObject samlObject) throws MarshallingException {
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                .getMarshaller(samlObject);
        Element element = marshaller.marshall(samlObject);

        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(element), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to marshall SAML object", e);
        }
    }

    /**
     * 使用 HTTP-Redirect 绑定发送 LogoutRequest
     *
     * SAML HTTP-Redirect 绑定规范：
     * 1. 将 SAML 消息 Deflate 压缩
     * 2. Base64 编码
     * 3. URL 编码后放入 SAMLRequest 参数
     * 4. 如有签名，生成 Signature 和 SigAlg 参数
     */
    public String sendLogoutRequest(LogoutRequest logoutRequest,
                                    String relayState) throws Exception {

        // 1. 序列化 LogoutRequest 为 XML
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                .getMarshaller(logoutRequest);
        Element element = marshaller.marshall(logoutRequest);

        // 2. 将 XML 转为字符串
        String xmlString = elementToString(element);

        // 3. Deflate 压缩 + Base64 编码
        byte[] deflated = deflateAndBase64(xmlString.getBytes("UTF-8"));
        String samlRequestParam = new String(deflated, "UTF-8");

        // 4. 构建 URL
        URIBuilder uriBuilder = new URIBuilder(idpSingleLogoutUrl);
        uriBuilder.addParameter("SAMLRequest", samlRequestParam);

        if (relayState != null && !relayState.isEmpty()) {
            uriBuilder.addParameter("RelayState", relayState);
        }

        // 5. 如果有签名，添加签名参数
        if (logoutRequest.isSigned()) {
            // 获取签名算法（与签名时一致）
            String sigAlg = logoutRequest.getSignature().getSignatureAlgorithm();
            uriBuilder.addParameter("SigAlg", sigAlg);

            // 构建待签名的 Query String（不含 Signature 参数）
            // 注意：参数必须按字母顺序排列
            String queryString = buildQueryStringToSign(uriBuilder);

            // 计算签名
            byte[] signatureBytes = signQueryString(queryString.getBytes("UTF-8"));
            String signatureParam = Base64.encodeBase64URLSafeString(signatureBytes);
            uriBuilder.addParameter("Signature", signatureParam);
        }

        URI redirectUri = uriBuilder.build();

        // 6. 执行 HTTP GET 重定向（实际场景中应返回 URL 给前端做重定向）
        // 此处演示直接发送请求
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(redirectUri);
            // 注意：实际 SAML 流程中，应由用户浏览器发起重定向，而非服务端直接请求
            // 此处仅用于演示
            return httpClient.execute(httpGet, response -> {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode >= 200 && statusCode < 300) {
                    return "LogoutRequest sent successfully";
                } else {
                    return "Failed: " + statusCode;
                }
            });
        }
    }

    // ========== 辅助方法 ==========

    private String elementToString(Element element) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(element), new StreamResult(baos));
        return baos.toString("UTF-8");
    }

    private byte[] deflateAndBase64(byte[] input) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater);
        dos.write(input);
        dos.close();
        return Base64.encodeBase64(baos.toByteArray());
    }

    /**
     * 构建待签名的 Query String（不含 Signature 参数，参数按字母序排列）
     */
    private String buildQueryStringToSign(URIBuilder uriBuilder) {
        // 实际实现需要提取所有参数（除 Signature 外），按字母序排序后拼接
        // 此处简化，完整实现可参考 OpenSAML 的 HTTPRedirectDeflateEncoder
        try {
            return uriBuilder.build().getRawQuery();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] signQueryString(byte[] data) throws Exception {
        java.security.Signature signer =
                java.security.Signature.getInstance("SHA256withRSA");
        signer.initSign(signingCredential.getPrivateKey());
        signer.update(data);
        return signer.sign();
    }
}
