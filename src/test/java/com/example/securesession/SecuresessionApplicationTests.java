package com.example.securesession;

import com.example.securesession.util.AesUtil;
import com.example.securesession.util.Base64Util;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest
class SecuresessionApplicationTests {

    @Autowired
    AesUtil aesUtil;

    @Autowired
    Base64Util base64Util;

    @Test
    public void proveAES () throws Exception {
        //given
        byte[] sessionKey = aesUtil.getSessionKey();

        String plainText = "Hello World";

        //when
        String encryptedData = base64Util.encodingToString(aesUtil.encryptDataToByte(plainText, sessionKey));
        String decryptedData = aesUtil.decryptData(base64Util.decodingToByte(encryptedData), sessionKey);

        //then
        Assertions.assertEquals(decryptedData, plainText);

    }

}
