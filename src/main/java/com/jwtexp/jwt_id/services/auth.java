package com.jwtexp.jwt_id.services;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
/* import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam; */
import org.springframework.web.bind.annotation.RestController;

@RestController
public class auth {
  
  @Secured("ADMIN")
  @GetMapping({"/hola", "/hola2"})
  public String Hola() {
    return "hola";
  }

  /* @PostMapping("/login")
  public void login(
    @RequestParam("username") final String username,
    @RequestParam("password") final String password) {

    return;
  } */

}
