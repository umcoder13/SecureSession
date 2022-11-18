package com.example.securesession.controller;

import com.example.securesession.service.SecureService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TransmitController {

    private final SecureService secureService;


}
