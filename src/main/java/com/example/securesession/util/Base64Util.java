package com.example.securesession.util;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
public class Base64Util {

    public byte[] encodingToByte(String data) {
        return Base64.getEncoder().encode(data.getBytes());
    }

    public byte[] decodingToByte(String encodingData) {
        return Base64.getDecoder().decode(encodingData);
    }

    public String encodingToString(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public String decodingToString(byte[] encodingData) {
        byte[] decodedBytes = Base64.getDecoder().decode(encodingData);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }
}
