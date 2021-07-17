package com.jwtexp.jwt_id;

import com.jwtexp.jwt_id.jwt.JWTAbstract;
import com.jwtexp.jwt_id.jwt.JWTAuthFilter;
import com.jwtexp.jwt_id.jwt.JWTAuthorization;
import com.jwtexp.jwt_id.services.JpaUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled =true)
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {
  
  @Autowired
  private JWTAbstract JWT;

  @Bean
  public UserDetailsService userDetailsService() {
      return new JpaUserDetailsService();
  }

  @Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
      DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
      authProvider.setUserDetailsService(userDetailsService());
      authProvider.setPasswordEncoder(passwordEncoder());
        
      return authProvider;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.authenticationProvider(authenticationProvider());
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {

    http.authorizeRequests().antMatchers("/", "/hola").permitAll()
            .anyRequest().authenticated()
            .and()
            
      .addFilter(new JWTAuthFilter(authenticationManager(), JWT))
      .addFilter(new JWTAuthorization(authenticationManager(), JWT))
      .csrf().disable()
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //sin estado
  } 
}
