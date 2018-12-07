/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package io.gravitee.policy.apikey.configuration;

/**
 * a configured {@link Response}.<br/>
 * created 06.12.2018
 *
 * @author Oliver Kelling, https://github.com/k-oliver
 * @since 1.6.3
 */
public class Response {

    private String contentType;
    private ErrorType type;
    private Integer statusCode;
    private String content;

    /**
     * @return the contentType
     * @since 1.6.3
     */
    public String getContentType() {
        return this.contentType;
    }

    /**
     * @param contentType
     *        the contentType to set
     * @since 1.6.3
     */
    public void setContentType(final String contentType) {
        this.contentType = contentType;
    }

    /**
     * @return the type
     * @since 1.6.3
     */
    public ErrorType getType() {
        return this.type;
    }

    /**
     * @param type
     *        the type to set
     * @since 1.6.3
     */
    public void setType(final ErrorType type) {
        this.type = type;
    }

    /**
     * @return the statusCode
     * @since 1.6.3
     */
    public Integer getStatusCode() {
        return this.statusCode;
    }

    /**
     * @param statusCode
     *        the statusCode to set
     * @since 1.6.3
     */
    public void setStatusCode(final Integer statusCode) {
        this.statusCode = statusCode;
    }

    /**
     * @return the content
     * @since 1.6.3
     */
    public String getContent() {
        return this.content;
    }

    /**
     * @param content
     *        the content to set
     * @since 1.6.3
     */
    public void setContent(final String content) {
        this.content = content;
    }

    /**
     * {@inheritDoc}
     * 
     * @see java.lang.Object#hashCode()
     * @since 1.6.3
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (this.content == null ? 0 : this.content.hashCode());
        result = prime * result + (this.contentType == null ? 0 : this.contentType.hashCode());
        result = prime * result + (this.statusCode == null ? 0 : this.statusCode.hashCode());
        result = prime * result + (this.type == null ? 0 : this.type.hashCode());
        return result;
    }

    /**
     * {@inheritDoc}
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     * @since 1.6.3
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof Response)) {
            return false;
        }
        final Response other = (Response)obj;
        if (this.content == null) {
            if (other.content != null) {
                return false;
            }
        } else if (!this.content.equals(other.content)) {
            return false;
        }
        if (this.contentType == null) {
            if (other.contentType != null) {
                return false;
            }
        } else if (!this.contentType.equals(other.contentType)) {
            return false;
        }
        if (this.statusCode == null) {
            if (other.statusCode != null) {
                return false;
            }
        } else if (!this.statusCode.equals(other.statusCode)) {
            return false;
        }
        if (this.type != other.type) {
            return false;
        }
        return true;
    }

    /**
     * {@inheritDoc}
     * 
     * @see java.lang.Object#toString()
     * @since 1.6.3
     */
    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("Response[");
        if (this.contentType != null) {
            builder.append("contentType=");
            builder.append(this.contentType);
            builder.append(", ");
        }
        if (this.type != null) {
            builder.append("type=");
            builder.append(this.type);
            builder.append(", ");
        }
        if (this.statusCode != null) {
            builder.append("statusCode=");
            builder.append(this.statusCode);
            builder.append(", ");
        }
        if (this.content != null) {
            builder.append("content=");
            builder.append(this.content);
        }
        builder.append("]");
        return builder.toString();
    }
}
