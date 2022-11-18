package com.example.securesession;

import com.example.securesession.service.KeySecureService;
import com.example.securesession.util.RsaUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;

@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest
public class KeySecureTest {

    @Autowired
    RsaUtil rsaUtil;

    @Autowired
    KeySecureService keySecureService;



    @Test
    public void existKey() throws Exception {
        //given

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        String p12Password = "000000";

        //when
        Path filePath = Paths.get(File.separatorChar + "key", File.separatorChar + "pkcs12.p12");
        keystore.load(this.getClass().getClassLoader().getResourceAsStream(filePath.toString()), p12Password.toCharArray());
        PrivateKey key = (PrivateKey) keystore.getKey("1", p12Password.toCharArray());

        //then
        Assertions.assertNotNull(key);


    }

    @Test
    public void decRsaTest() throws Exception {
        //given
        String encryptedText = "ba7Ty9TG77zZvYeN5h9DvSGSSV5QymGbrMFfzAgfZUuxZ3BMXPs8jh6cVWD7NM/TkO7GIT63c9qo8wULMqQNfrwEOSlFWX0+o0Q0CYbhmfqA8WVzrsh8omNuVumFg79dPkJ/36RGod8sEtjF7XoXr01Ovzg3Md9rIB+xUKhHawpqOXs1iL3cU9IjddY3uGqrVuK7qetSWoqWRQFU5pNXy6ImOXTSj7jWNy14LHIZAJuUbXXmFfXsAnZLzI+S0yYxeS9X+Vr/wOfjHxMsDy+XEzBXS/seUi5ClpBHbcEA9NJyxpT870paFqCTYp+uf2RmhQuypOZd4tRe2B5Pic4CXQ==";

        //when
        String decryptedText = rsaUtil.decRSA(encryptedText, keySecureService.saveKey());

        //then
        log.info(decryptedText);
        Assertions.assertEquals("Hello World!", decryptedText);


    }
}
