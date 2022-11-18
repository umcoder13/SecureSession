package com.example.securesession.service;

import com.example.securesession.util.AesUtil;
import com.example.securesession.util.Base64Util;
import com.example.securesession.util.RedisUtil;
import com.example.securesession.util.RsaUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecureService {
    private final AesUtil aesUtil;
    private final Base64Util base64Util;
    private final RsaUtil rsaUtil;
    private final RedisUtil redisUtil;

    // 공용키 반환 및 개인키 저장
    public String getPublicKeyAndSavePrivateKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = rsaUtil.genRSAKeyPair();
        if (redisUtil.existData("prk")) {
            redisUtil.deleteData("prk");
        }
        redisUtil.setDataExpire("prk", rsaUtil.privateKeyToBase64Encrypt(keyPair.getPrivate()), 60 * 60L);
        log.info(keyPair.getPublic().toString());
        return rsaUtil.publicKeyToBase64Encrypt(keyPair.getPublic());
    }

    // 평문 RSA 암호화
    public String encryptText(String text, String encryptedPubKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PublicKey pubKey = rsaUtil.getPublicKeyFromBase64Enc(encryptedPubKey);
        return rsaUtil.encRSA(text, pubKey);
    }

    // bytes 배열 RSA 암호화
    public String encryptBytes(byte[] bytes, String encryptedPubKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PublicKey pubKey = rsaUtil.getPublicKeyFromBase64Enc(encryptedPubKey);
        return rsaUtil.encRSAByteArray(bytes, pubKey);
    }

    // RSA로 복호화 된 암호 평문으로 반환
    public String decryptText(String encryptedText) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PrivateKey prk = rsaUtil.getPrivateKeyFromBase64Enc(redisUtil.getData("prk"));
        return rsaUtil.decRSA(encryptedText, prk);
    }

    // RSA로 복호화 된 암호 bytes 배열로 반환
    public byte[] decryptToBytes(String encryptedText) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PrivateKey prk = rsaUtil.getPrivateKeyFromBase64Enc(redisUtil.getData("prk"));
        return rsaUtil.decRSAToBytes(encryptedText, prk);
    }

    // 세션키와 kcv 생성
    public byte[] getSessionKeyAndKcv() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        byte[] sessionKey = aesUtil.getSessionKey();
        byte[] kcv = aesUtil.getKcv(sessionKey);
        return aesUtil.concatByteArrays(sessionKey, kcv);
    }

    // 세션키와 kcv 검증. 검증여부에 따라 boolean값 반환 및 검증 성공시 redis에 세션키 저장.
    public boolean verifySessionKeyAndKcv(byte[] decryptedSkAndKcv) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        boolean isVerified = aesUtil.verifyKcv(decryptedSkAndKcv);
        if(isVerified) {
            String sessionKey = Base64.getEncoder().encodeToString(aesUtil.findSessionKeyFromSkAndKcv(decryptedSkAndKcv));
            if(redisUtil.existData("sk")) {
                redisUtil.deleteData("sk");
            }
            redisUtil.setDataExpire("sk", sessionKey, 60 * 60L);
        }

        return isVerified;
    }

    public String encryptPlainText(String plainText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] sk = base64Util.decodingToByte(redisUtil.getData("sk"));
        return base64Util.encodingToString(aesUtil.encryptDataToByte(plainText, sk));
    }

    public String decryptData(String encryptedData) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] sk = base64Util.decodingToByte(redisUtil.getData("sk"));
        return aesUtil.decryptData(base64Util.decodingToByte(encryptedData), sk);
    }


}
