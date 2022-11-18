package com.example.securesession.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
@Component
public class AesUtil {

    String alg = "AES/CBC/PKCS5Padding";
    String iv = "0000000000000000";

    public byte[] getSessionKey() throws NoSuchAlgorithmException {
        byte[] sessionKey = new byte[32];
        SecureRandom ran = SecureRandom.getInstanceStrong();
        ran.nextBytes(sessionKey);
        return sessionKey;
    }


    public byte[] getKcv(byte[] sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //16byte 0x00
        String data = "0000000000000000";
        byte[] encrypted = encryptDataToByte(data, sessionKey);
        return Arrays.copyOf(encrypted, 3);
    }

    public byte[] encryptDataToByte(String plainData, byte[] sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(alg);
        SecretKeySpec keySpec = new SecretKeySpec(sessionKey, "AES");

        IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec);

        return cipher.doFinal(plainData.getBytes());
    }

    public byte[] concatByteArrays(byte[] sessionKey, byte[] kcv) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        output.write(sessionKey);
        output.write(kcv);

        return output.toByteArray();
    }

    public boolean verifyKcv(byte[] bytes) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] sessionKey = findSessionKeyFromSkAndKcv(bytes);
        byte[] kcv = getKcv(sessionKey);

        log.info(Arrays.toString(kcv));

        byte[] kcvFromRsa = Arrays.copyOfRange(bytes, bytes.length - 3, bytes.length);

        log.info(Arrays.toString(kcvFromRsa));

        return Arrays.equals(kcv, kcvFromRsa);

    }

    public byte[] findSessionKeyFromSkAndKcv(byte[] bytes) {
        return Arrays.copyOf(bytes, 32);
    }

    public String decryptData(byte[] encryptedData, byte[] sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey secretKey = new SecretKeySpec(sessionKey, "AES");
        Cipher cipher = Cipher.getInstance(alg);
        cipher.init(Cipher.DECRYPT_MODE,secretKey, new IvParameterSpec(iv.getBytes()));

        return new String (cipher.doFinal(encryptedData));
    }


}
