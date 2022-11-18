package com.example.securesession.service;

import com.example.securesession.util.Base64Util;
import com.example.securesession.util.RsaUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;

@Service
@RequiredArgsConstructor
public class KeySecureService {

    private final RsaUtil rsaUtil;
    private final Base64Util base64Util;

    public PrivateKey saveKey() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Path filePath = Paths.get(File.separatorChar + "key", File.separatorChar + "pkcs12.p12");
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        String p12Password = "000000";
        keystore.load(this.getClass().getClassLoader().getResourceAsStream(filePath.toString()), p12Password.toCharArray());
        return (PrivateKey) keystore.getKey("1", p12Password.toCharArray());
    }

    public String decRSAToKey (String encrypted) throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return rsaUtil.decRSA(encrypted, saveKey());

    }



}