package com.aflac.everwell.authentication.config.resource;

import lombok.Data;

@Data
public class ErrorResource {

    private int status; // The http status code
    private String code; // The internal, readable code
    private String message;

    public ErrorResource(int status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
