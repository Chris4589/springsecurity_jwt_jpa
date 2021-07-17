package com.jwtexp.jwt_id.jwt;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;

public class JWTAuthorization extends BasicAuthenticationFilter {

  private JWTAbstract Jwt;
  //public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

  public JWTAuthorization(AuthenticationManager authenticationManager, JWTAbstract Jwt) {
    super(authenticationManager);
    this.Jwt = Jwt;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
      
    String header = request.getHeader("token");

    if (!isReqAuth(header)) {
      chain.doFilter(request, response);
      return;
    }
    boolean validToken = true;
    Jws<Claims> token = null;
    try {
      
      System.out.println("validToken H: " + header);
      System.out.println("validToken Auth: " + header.replace("Bearer ", ""));

      token = this.Jwt.verifity(header.replace("Bearer ", ""));
      /* token = Jwts.parserBuilder()
        .setSigningKey(SECRET_KEY) 
        .build()
        .parseClaimsJws(header.replace("Bearer ", "")); */

      validToken = true;
      

    }
    catch (JwtException | IllegalArgumentException ex) {       // (5)
        
      validToken = false;
      System.out.println("validToken false: " + ex);
    }

    UsernamePasswordAuthenticationToken authToken = null;
    if (validToken) {

      String username = token.getBody().getSubject();
      Object roles = token.getBody().get("roles"); //JWTAuthFilter

      Collection<? extends GrantedAuthority> authorities = Arrays
				.asList(new ObjectMapper()
          .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
          .readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class)
        );
      
      System.out.println("valido " + authorities);
      authToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
    
    }
    SecurityContextHolder.getContext().setAuthentication(authToken);
    chain.doFilter(request, response);
  }

  protected boolean isReqAuth(String header) {

    if (header == null || !header.startsWith("Bearer ")) {
      return false;
    }
    return true;
  }

}
