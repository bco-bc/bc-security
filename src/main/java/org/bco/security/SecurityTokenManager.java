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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Maintains security tokens. After user sign in, a new security token is 
 * associated with that user. After a server restart, all previous tokens are lost.
 * @author Andr&#233; H. Juffer, Biocenter Oulu
 * @param <T> Type user specification.
 */
public class SecurityTokenManager<T> {
    
    private final Map<SecurityToken, T> tokens_;
    
    public SecurityTokenManager()
    {
        tokens_ = new ConcurrentHashMap<>();
    }
    
    /**
     * Create new security token.
     * @param spec User specification.
     * @return Session identifier.
     */
    public SecurityToken createNew(T spec)
    {
        //SecurityToken securityToken = SecurityToken.generate();
        SecurityToken securityToken = SecurityToken.valueOf("123456789qwerty-test");
        tokens_.put(securityToken, spec);
        return securityToken;
    }
    
    /**
     * Ends session.Usually called after signing out.
     * @param securityToken Security token.
     */
    public void removeSecurityToken(SecurityToken securityToken)
    {
        tokens_.remove(securityToken);
    }
    
    /**
     * Returns user specification.
     * @param securityToken Security token.
     * @return User specification.
     */
    public T getUser(SecurityToken securityToken)
    {
        if ( !this.exists(securityToken) ) {
            throw new NullPointerException(
                securityToken.stringValue() + ": No such user specification."
            );
        }
        return tokens_.get(securityToken);
    }
    
    /**
     * Does given security token exists?
     * @param securityToken Security token.
     * @return Result.
     */
    public boolean exists(SecurityToken securityToken)
    {
        return tokens_.containsKey(securityToken);
    }
    
}
