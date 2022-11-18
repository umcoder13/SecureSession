package com.example.securesession.util;

import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class RsaUtil {
    public KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048, new SecureRandom());
        return gen.genKeyPair();
    }


    public String encRSA(String plainText, PublicKey puk) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, puk);

        byte[] bytePlain = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(bytePlain);
    }

    public String encRSAByteArray (byte[] bytes, PublicKey puk) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, puk);

        byte[] bytePlain = cipher.doFinal(bytes);
        return Base64.getEncoder().encodeToString(bytePlain);
    }


    public String decRSA (String encrypted, PrivateKey prk) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, prk);
        byte[] bytePlain = cipher.doFinal(byteEncrypted);
        return new String(bytePlain, StandardCharsets.UTF_8);
    }

    public byte[] decRSAToBytes (String encrypted, PrivateKey prk) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, prk);
        return cipher.doFinal(byteEncrypted);
    }


    public PublicKey getPublicKeyFromBase64Enc(String base64Puk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodeB64Puk = Base64.getDecoder().decode(base64Puk);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodeB64Puk));
    }

    public PrivateKey getPrivateKeyFromBase64Enc(String bas64Prk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedB64Prk = Base64.getDecoder().decode(bas64Prk);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedB64Prk));
    }


    public String publicKeyToBase64Encrypt(PublicKey puk) {
        return Base64.getEncoder().withoutPadding().encodeToString(puk.getEncoded());
    }

    public String privateKeyToBase64Encrypt(PrivateKey prk) {
        return Base64.getEncoder().encodeToString(prk.getEncoded());
    }
}
