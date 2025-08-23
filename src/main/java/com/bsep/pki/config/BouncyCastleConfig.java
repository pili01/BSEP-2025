package com.bsep.pki.config;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Configuration
public class BouncyCastleConfig {

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
    }
}