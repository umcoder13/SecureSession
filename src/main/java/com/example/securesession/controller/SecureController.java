package com.example.securesession.controller;

import com.example.securesession.dto.DecryptRequestDto;
import com.example.securesession.dto.EncryptRequestDto;
import com.example.securesession.service.SecureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Slf4j
@RestController
@RequiredArgsConstructor
public class SecureController {

    private final SecureService secureService;

    // rsa 공용키 발행
    @GetMapping("/pub-key")
    public ResponseEntity<String> sendPublicKey() throws NoSuchAlgorithmException {
        return ResponseEntity.ok(secureService.getPublicKeyAndSavePrivateKey());
    }

    // rsa 공용키로 평문 암호화
    @PostMapping("/encrypt")
    public ResponseEntity<String> encryptPlainText(@RequestBody EncryptRequestDto dto) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        return ResponseEntity.ok(secureService.encryptText(dto.getText(), dto.getKey()));
    }

    // 암호화된 평문 rsa 복호화
    @PostMapping("/decrypt")
    public ResponseEntity<String> decryptEncryptText(@RequestBody DecryptRequestDto dto) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        return ResponseEntity.ok(secureService.decryptText(dto.getText()));
    }

    // 세션키와 kcv 발행
    @PostMapping("/make-kcv")
    public ResponseEntity<String> sendSessionKeyAndKcv(@RequestBody EncryptRequestDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException, InvalidKeySpecException {
        return ResponseEntity.ok(secureService.encryptBytes(secureService.getSessionKeyAndKcv(), dto.getKey()));
    }

    // 세션키, kcv 검증
    @PostMapping("/verify-kcv")
    public ResponseEntity<String> verifySessionKeyAndKcv(@RequestBody DecryptRequestDto dto) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        if (secureService.verifySessionKeyAndKcv(secureService.decryptToBytes(dto.getText()))) {
            return ResponseEntity.ok("인증성공!");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("kcv가 일치하지 않습니다");
    }

}
