package com.bsep.pki.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class Recaptcha {

    @Value("${recaptcha.site-key}")
    private String secret;
    public Recaptcha(){}

    public boolean verifyRecaptcha(String token) {
        String url = "https://www.google.com/recaptcha/api/siteverify?secret=" + secret + "&response=" + token;

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.postForEntity(url, null, Map.class);

        Map body = response.getBody();
        return body != null && Boolean.TRUE.equals(body.get("success"));
    }
}