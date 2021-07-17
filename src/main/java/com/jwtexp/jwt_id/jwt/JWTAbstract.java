package com.jwtexp.jwt_id.jwt;

import java.security.Key;
import java.util.Collection;
import java.util.Date;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.IOException;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTAbstract {

  public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
  
  public String sign(Authentication authResult)  
  throws IOException, JsonProcessingException {
    
    Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();
    
    Claims claims = Jwts.claims();
    claims.put("roles", new ObjectMapper().writeValueAsString(roles));
    
    String token = Jwts.builder()
        .setClaims(claims)
        .setSubject(authResult.getName())
        .signWith(SECRET_KEY)
        .setExpiration(new Date(System.currentTimeMillis() + 3600000L))
        .compact(); //construimos el token

    return token;
  }

  public Jws<Claims> verifity(String tokenHeader) throws JwtException, IllegalArgumentException {
    Jws<Claims> token = null;

    token = Jwts.parserBuilder()
        .setSigningKey(SECRET_KEY) 
        .build()
        .parseClaimsJws(tokenHeader);

    return token;
  }

}
