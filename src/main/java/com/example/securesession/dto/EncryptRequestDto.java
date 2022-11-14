package com.example.securesession.dto;

import lombok.Getter;

@Getter
public class EncryptRequestDto {
    private String text;
    private String key;
}
