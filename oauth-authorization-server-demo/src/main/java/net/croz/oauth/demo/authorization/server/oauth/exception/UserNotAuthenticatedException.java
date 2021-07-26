package net.croz.oauth.demo.authorization.server.oauth.exception;

public class UserNotAuthenticatedException extends Exception {

    public UserNotAuthenticatedException(String message) {
        super(message);
    }
}
