package com.gofar.mfa.dto;

import lombok.Data;

import java.util.function.Consumer;

@Data
public class ApiResponse {
    private boolean success;
    private String message;
    private Object data;

    public static ApiResponse ok(String message) {
        ApiResponse r = new ApiResponse();
        r.success = true;
        r.message = message;
        return r;
    }

    public static ApiResponse ok(String message, Object data) {
        ApiResponse r = ok(message);
        r.data = data;
        return r;
    }

    public static ApiResponse error(String message) {
        ApiResponse r = new ApiResponse();
        r.success = false;
        r.message = message;
        return r;
    }

    public ApiResponse tap(Consumer<ApiResponse> consumer) {
        consumer.accept(this);
        return this;
    }
}
