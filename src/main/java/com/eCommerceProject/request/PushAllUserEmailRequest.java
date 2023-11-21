package com.eCommerceProject.request;

import lombok.Data;

import jakarta.validation.constraints.NotNull;

@Data
public class PushAllUserEmailRequest {

    @NotNull
    private String body;

    @NotNull
    private String title;
}
