package com.dev.apigateway.Utils;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JWTToken {

    private static final String Secret = "secret2313u2483245863r2fyquyqwuud6eryueadfeyfdfja";
    private static final long EXPIRATION_TIME = 432_00_000; // 12 hrs

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(Secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
//
    public Claims validateToken(final String token) {
       return  Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
    }
//private SecretKey key;
//
//    @PostConstruct
//    public void init() {
//        key = Keys.hmacShaKeyFor(Secret.getBytes());
//    }
//    public Claims getClaimsFromToken(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }

    public boolean isTokenExpired(String token) {
        return validateToken(token).getExpiration().before(new Date());
    }
}
