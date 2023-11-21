package com.eCommerceProject.request;

import lombok.Data;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;

@Data
public class PushEmailRequest {

    @Email
    private String eMail;

    @NotNull
    private String body;

    @NotNull
    private String title;

}
