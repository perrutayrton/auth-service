package com.auth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class JwtService {

    public UUID ExtractUUID(String token) {

        DecodedJWT decodedJWT = JWT.decode(token);
        String userId = decodedJWT.getClaim("id").asString();

        return UUID.fromString(userId);
    }
}
