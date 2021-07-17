package com.jwtexp.jwt_id.jwt;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwtexp.jwt_id.models.Usuario;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


public class JWTAuthFilter extends UsernamePasswordAuthenticationFilter {
  
  private AuthenticationManager authManager;
  private JWTAbstract Jwt;
  //public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
  
  //constructor
  public JWTAuthFilter(AuthenticationManager authManager, JWTAbstract Jwt) {
    this.authManager = authManager;
    this.Jwt = Jwt;
    setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/logger",
    "POST"));
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException {

    String username = obtainUsername(request); // es igual a request.getParameter("username");
		username = (username != null) ? username : "";
		username = username.trim();
		String password = obtainPassword(request);
		password = (password != null) ? password : "";

    //para recibir un JSON 
    if (username == "" && password == "") {
      try {
        Usuario user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
        username = user.getUsername();
        password = user.getPassword();
      } catch (JsonParseException e) {
        e.printStackTrace();
      } catch (JsonMappingException e) {
        e.printStackTrace();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }

    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

    return authManager.authenticate(authToken);
  }

  //metodo llamado despues de doFilter, si es correcto
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    //authResult trae los datos de spring security (name, roles)

    String token = this.Jwt.sign(authResult);
    
    response.addHeader("Authorization", "Bearer " + token); //se envia en los headers
    Map<String, Object> body = new HashMap<String, Object>();
    System.out.println("token: " + token);
    body.put("token", token);
    body.put("roles", authResult.getAuthorities());
    body.put("user", authResult.getName());
    body.put("error", false);
    // ObjectMapper() lo hace JSON
    response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    response.setStatus(200);
    response.setContentType("application/json");

    //super.successfulAuthentication(request, response, chain, authResult);//tengo propio quito el default
  }
  //metodo llamado por onFilter si esta mal la pw
  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    
        Map<String, Object> body = new HashMap<String, Object>();

    body.put("msg", "Ocurrio un error: " + failed.getMessage());
    body.put("error", true);
    // ObjectMapper() lo hace JSON
    response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    response.setStatus(401);
    response.setContentType("application/json");

  }

  //filtros antes de request y chain.dofilter es para que siga normal y marca un despue
 /*  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    super.doFilter(request, response, chain);//sigue el proceso normal despues de pasar el filtro
  } */
}
