package net.croz.oauth.demo.authorization.server.oauth.exception;


import lombok.Getter;
import net.croz.oauth.demo.authorization.server.oauth.model.OAuth2ErrorType;

@Getter
public class InvalidParameterException extends Exception {

    private final OAuth2ErrorType errorType;

    private final String parameter;

    public InvalidParameterException(OAuth2ErrorType errorType, String parameter, String message) {
        super(message);
        this.errorType = errorType;
        this.parameter = parameter;
    }

    public static InvalidParameterException invalidRequest(String parameter, String message) {
        return new InvalidParameterException(OAuth2ErrorType.invalid_request, parameter, message);
    }

    public static InvalidParameterException invalidScope(String parameter, String message) {
        return new InvalidParameterException(OAuth2ErrorType.invalid_scope, parameter, message);
    }

    public static InvalidParameterException unsupportedResponseType(String parameter, String message) {
        return new InvalidParameterException(OAuth2ErrorType.unsupported_response_type, parameter, message);
    }
}
