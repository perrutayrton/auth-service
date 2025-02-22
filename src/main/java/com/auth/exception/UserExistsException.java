package com.auth.exception;

public class UserExistsException extends RuntimeException {

    public UserExistsException() {

        super("Usuário já cadastrado");
    }
}
