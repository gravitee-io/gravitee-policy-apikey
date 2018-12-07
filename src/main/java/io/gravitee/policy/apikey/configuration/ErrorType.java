package io.gravitee.policy.apikey.configuration;

/**
 * a type of error to configure a response for.<br/>
 * erzeugt am 06.12.2018
 *
 * @author Oliver Kelling, https://github.com/k-oliver
 * @since 1.6.3
 */
public enum ErrorType {

    /**
     * no API key was send.
     *
     * @since 1.6.3
     */
    MISSING,

    /**
     * API key is wrong, expired or revoked.
     *
     * @since 1.6.3
     */
    WRONG_EXPIRED_REVOKED
}
