package com.gofar.mfa.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.function.Consumer;

@Data
@Schema(name = "ApiResponse", description = "API response")
public class ApiResponse {
    @Schema(description = "Indicates if the request was successful or not", example = "true")
    private boolean success;
    @Schema(description = "Execution message of the request", example = "User registered successfully")
    private String message;
    @Schema(description = "Response data", example = "{}")
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
