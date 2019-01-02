/*
 * The MIT License
 *
 * Copyright 2019 André H. Juffer, Biocenter Oulu
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

import java.util.Objects;

/**
 * Holds a security token for authorization purposes.
 * @author Andr&#233; H. Juffer, Biocenter Oulu
 */
public class SecurityToken implements Comparable<SecurityToken>
{    
    private final String value_;
    
    private SecurityToken(String value)
    {
       value_ = value;
    }
    
    /**
     * Returns value.
     * @return Value.
     */
    public String stringValue()
    {
        return value_;
    }

    @Override
    public int compareTo(SecurityToken other) 
    {
        return value_.compareTo(other.stringValue());
    }
    
    @Override
    public boolean equals(Object other)
    {
        if ( other == null ) {
            return false;
        }
        if ( other == this ) {
            return true;
        }
        if ( !(other instanceof SecurityToken) ) {
            return false;
        }
        SecurityToken token = (SecurityToken)other;
        return this.stringValue().equals(token.stringValue());
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 61 * hash + Objects.hashCode(this.value_);
        return hash;
    }
    
    /**
     * Returns new instance.
     * @param value Value. Must neither be null nor empty.
     * @return New instance.
     */
    public static SecurityToken valueOf(String value)
    {
        if ( value == null ) {
            throw new NullPointerException("SecurityToken: value must not be null.");
        }
        if ( value.isEmpty() ) {
            throw new IllegalArgumentException("SecurityToken: value must not be empty.");
        }
        return new SecurityToken(value);
    }

}
