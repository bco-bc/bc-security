/*
 * The MIT License
 *
 * Copyright 2018 André H. Juffer, Biocenter Oulu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.bco.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Utilities for security tokens.
 * @author Andr&#233; H. Juffer, Biocenter Oulu
 */
public class SecurityTokenUtil {
    
    private static final String ALGORITHM = "HmacSHA256";
    private static final String BEARER = "bearer";
    private static final int BEARER_LENGTH = BEARER.length();
    private static final String KEY = "app_security";
    
    public static final String SECURITY_TOKEN_COOKIE_NAME = "app_security_token";    
    
    /**
     * Extracts security token from Cookie value.
     * @param request Request.
     * @return Value
     */
    public static SecurityToken extractFromRequest(HttpServletRequest request)
    {
        if ( request == null ) {
            throw new NullPointerException("Missing HTTP request.");
        }
        Cookie[] cks = request.getCookies();
        if ( cks == null ) {
            throw new NullPointerException("Missing security token.");
        }
        Collection<Cookie> cookies = Arrays.asList(cks);
        for (Cookie cookie : cookies) {
            if ( cookie.getName().equals(SECURITY_TOKEN_COOKIE_NAME) ) {
                String value = cookie.getValue();
                if ( value.isEmpty() || value.length() < 10 ) {
                    throw new IllegalArgumentException("Illegal security token value.");
                }
                return SecurityToken.valueOf(value);
            }
        }
        throw new NullPointerException("Missing security token.");
    }
    
    /**
     * Extracts security token from Authorization header.
     * @param request Request.
     * @return Security token.
     */
    public static SecurityToken extractFromAuthorizationHeader(HttpServletRequest request)
    {
        String authorization = request.getHeader("Authorization");
        if ( authorization == null ) {
            throw new NullPointerException("Missing authorization header.");
        }
        if ( authorization.isEmpty() ) {
            throw new IllegalArgumentException("Empty authorization header.");
        }
        String bearer = authorization.substring(0, BEARER_LENGTH).toLowerCase();
        if ( !bearer.equals(BEARER) ) {            
            throw new IllegalArgumentException("Illegal authorization header.");
        }
        return SecurityToken.valueOf(authorization.substring(BEARER_LENGTH).trim());
    }
    
    /**
     * Returns a security token.
     * @return Token.
     */
    static SecurityToken generate()
    {
        try {
            SecretKey secretKey = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(secretKey);
            String s = UUID.randomUUID().toString();
            byte[] hash = mac.doFinal(s.getBytes());
            return SecurityToken.valueOf(Base64.getEncoder().encodeToString(hash));
        } catch (InvalidKeyException | NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                "Cannot generate new security token. " + exception.getMessage(), exception
            );
        }
    }    
    
    /**
     * Creates cookie.
     * @param securityToken
     * @return Cookie.
     */
    public static Cookie makeCookie(SecurityToken securityToken)
    {
        Cookie cookie = 
            new Cookie(SECURITY_TOKEN_COOKIE_NAME, securityToken.stringValue());
        
        cookie.setSecure(true);
        cookie.setPath("/");
        int expiry = 30 * 24 * 60 * 60;  // Month.
        cookie.setMaxAge(expiry);
        return cookie;
        
    }
    
    /**
     * Creates a cookie that will be deleted.
     * @param securityToken Security token.
     * @return Cookie.
     */
    public static Cookie removeCookie(SecurityToken securityToken)
    {
        Cookie cookie = SecurityTokenUtil.makeCookie(securityToken);
        cookie.setMaxAge(0);
        return cookie;
    }
    
}
