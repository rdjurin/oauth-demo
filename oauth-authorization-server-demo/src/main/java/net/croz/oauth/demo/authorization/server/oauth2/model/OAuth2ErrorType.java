package net.croz.oauth.demo.authorization.server.oauth2.model;

/**
 * OAuth2 error types based on RFC6749: <link>https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1</link>
 *
 */
public enum OAuth2ErrorType {
    invalid_request,
    unauthorized_client,
    access_denied,
    unsupported_response_type,
    invalid_scope,
    server_error,
    temporarily_unavailable
}
