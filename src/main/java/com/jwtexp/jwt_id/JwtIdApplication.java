package com.jwtexp.jwt_id;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class JwtIdApplication {
	
	public static BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	public static void main(String[] args) {
		String bcryptPassword = passwordEncoder().encode("1234");
		System.out.println(bcryptPassword);
		SpringApplication.run(JwtIdApplication.class, args);
		
	}
	
	
	
}
