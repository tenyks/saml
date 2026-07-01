package com.bw.saml.idp;

import com.bw.saml.cc.pojo.AuthnRequestField;
import com.bw.saml.cc.service.AuthnRequestHandler;
import com.bw.saml.cc.service.SamlResponseGenerator;
import com.bw.saml.constants.Constants;
import org.apache.commons.lang.StringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.opensaml.util.URLBuilder;
import org.opensaml.xml.util.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * @author Xiaosy
 * @date 2017-11-14 14:59
 */
@RestController
@RequestMapping("/idp")
public class IdpController {

    @Autowired
    private AuthnRequestHandler authnRequestHandler;

    @Autowired
    private SamlResponseGenerator samlResponseGenerator;

    @Autowired
    private SamlRequestCache samlRequestCache;

    @GetMapping("/sso")
    public void sso(@RequestParam(required = false, name = "SAMLRequest") String SAMLRequest,
                    @RequestParam(required = false, name = "RelayState") String RelayState,
                    HttpServletRequest request, HttpServletResponse response) throws Exception {
        System.out.println("samlRequest = " + SAMLRequest);
        /**
         * 是否在idp端已登录
         */
        Cookie[]cookies = request.getCookies();
        String cookie_value = null;
        if(cookies != null){
            for(Cookie cookie:cookies){
                if(Constants.IDP_COOKIE_KEY.equalsIgnoreCase(cookie.getName())){
                    cookie_value = cookie.getValue();
                }
            }
        }

        String username = "unknown";
        if (cookie_value != null && Constants.IDP_COOKIE_VALUE.equalsIgnoreCase(cookie_value)) {
            //已登录，解析SAMLRequest对象,查找出用户信息
            String email = username + "@qq.com";
            AuthnRequestField authnRequestField = authnRequestHandler.handleAuthnRequest(SAMLRequest);
            String result = samlResponseGenerator.generateSamlResponse("", username, email, authnRequestField);
            response.reset();
            PrintWriter printWriter = response.getWriter();
            printWriter.write(samlResponseGenerator.getForm(authnRequestField.getAssertionConsumerServiceUrl(), RelayState, new Base64().encodeAsString(result.getBytes("utf-8"))));
            printWriter.flush();
            printWriter.close();
            return;
        } else {
            //重定向到登陆页面
            samlRequestCache.setSAMLRequest(SAMLRequest);
            samlRequestCache.setRelayState(RelayState);

            URLBuilder urlBuilder = new URLBuilder();
            urlBuilder.setPath("/login.html");
            urlBuilder.getQueryParams().add(new Pair<>("SAMLRequest", SAMLRequest));
            if (StringUtils.isNotEmpty(RelayState)) {
                urlBuilder.getQueryParams().add(new Pair<>("RelayState", RelayState));
            }

            response.sendRedirect(urlBuilder.buildURL());
            return;
        }
    }

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String logoutRequest = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n" +
                "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n" +
                "ID=\"lizhongyun\"\n" +
                "Version=\"2.0\"\n" +
                "IssueInstant=\"2026-06-30T21:49:06Z\"\n" +
                "Destination=\"https://auth.air.gdrising.com.cn/mounisso/v1/cas/logout\"\n" +
                ">\n" +
                "<saml:Issuer>http://MyLinuxPC:48080/idp/logout</saml:Issuer>\n" +
                "<saml:NameID SPNameQualifier=\"http://MyLinuxPC:48080/idp/logout\"\n" +
                "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"\n" +
                ">lizhongyun</saml:NameID>\n" +
                "</samlp:LogoutRequest>";

        String samlRequest = new org.apache.commons.codec.binary.Base64().encodeAsString(logoutRequest.getBytes(StandardCharsets.UTF_8));

        response.sendRedirect("https://auth.air.gdrising.com.cn/mounisso/v1/cas/logout?RelayState="+System.currentTimeMillis() + "&SAMLRequest="+samlRequest);

    }

    @PostMapping("/logout")
    public void logoutCallback(HttpServletRequest request) {
        System.out.println("request = " + request);
    }

    @PostMapping("/auth")
    public LoginResponse login(@RequestParam String username, @RequestParam String password,
                               @RequestParam String domainName,
                               HttpServletRequest req, HttpServletResponse res) throws Exception {
        LoginResponse loginResponse = new LoginResponse();

        if ("Yixun@li2026".equals(password)) {
            String email = username + "@qq.com";
            //鉴权通过
            System.out.println("auth pass...");
            AuthnRequestField authnRequestField = authnRequestHandler.handleAuthnRequest(samlRequestCache.getSAMLRequest());
            System.out.println(authnRequestField);
            String result = samlResponseGenerator.generateSamlResponse(domainName, username, email, authnRequestField);
            res.reset();
            Cookie cookie = new Cookie(Constants.IDP_COOKIE_KEY,Constants.IDP_COOKIE_VALUE);
            cookie.setPath("/");
            res.addCookie(cookie);

            System.out.println("SAMLResponse => " + result);
            System.out.println("RelayState => " + samlRequestCache.getRelayState());

            PrintWriter printWriter = res.getWriter();
            String responseBase64 = new Base64().encodeAsString(result.getBytes(StandardCharsets.UTF_8));
            printWriter.write(samlResponseGenerator.getForm(authnRequestField.getAssertionConsumerServiceUrl(),
                    samlRequestCache.getRelayState(), responseBase64));
            printWriter.flush();
            printWriter.close();
            return null;
        }

        loginResponse.setCode(1);
        return loginResponse;
    }

    public static void main(String[] args) throws Exception {
        String input = "fZHNbsIwEITvfYrI98T5A1KLBKWgqkigphB66CUyxoAlYqdeh9K3ryEg0UN7XGnmm9XMcHSqD86RaxBKpijwfORwydRGyF2KVuWzm6BR9jAEWh/ChuSt2csF/2w5GCcH4NpY31hJaGuul1wfBeOrxSxFe2MaIBhT6/Co0N5uowVYqsdU7TGJa9VKAaDwMcDQYMoAi01T7aA6Z1WC1pXkX8iZ2Cghqbn8d6Za6Px7JmR7KsYkTvzEPxuxRSFnOklRvnhjj1EUDHou7THmWsnWTWI/dGkcMr6OtpzGW6sFaPlUgqHSpCj0w77r993IL4OIRCEJBl6QxB/IKbQyiqnDk5BdK62WRFEQQCStORDDyDKfz0jo+WTdiYC8lGXhFq/LEjnvt3bDc7u2bwmk6/N/VnMNRllXP7l8rO8J/wPobSCU/TXDEN+js+v5e+jsBw==";
        byte[] decodedBytes = new org.apache.commons.codec.binary.Base64().decode(input.getBytes("UTF-8"));
        System.out.println(new String(inflate(decodedBytes, true)));

    }

    private static byte[] inflate(byte[] bytes, boolean nowrap) throws Exception {

        Inflater decompressor = null;
        InflaterInputStream decompressorStream = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            decompressor = new Inflater(nowrap);
            decompressorStream = new InflaterInputStream(new ByteArrayInputStream(bytes),
                    decompressor);
            byte[] buf = new byte[1024];
            int count;
            while ((count = decompressorStream.read(buf)) != -1) {
                out.write(buf, 0, count);
            }
            return out.toByteArray();
        } finally {
            if (decompressor != null) {
                decompressor.end();
            }
            try {
                if (decompressorStream != null) {
                    decompressorStream.close();
                }
            } catch (IOException ioe) {
                /*ignore*/
                ioe.printStackTrace();
            }
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ioe) {
                /*ignore*/
                ioe.printStackTrace();
            }
        }
    }
}
