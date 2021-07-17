package com.jwtexp.jwt_id.services;

import java.util.ArrayList;
import java.util.List;

import com.jwtexp.jwt_id.models.Role;
import com.jwtexp.jwt_id.models.Usuario;
import com.jwtexp.jwt_id.models.dao.IUsuarioDao;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;


//@Service("jpaUserDetailsService")
public class JpaUserDetailsService implements UserDetailsService { //interfaz JPA default UserDetailsService

	@Autowired
	private IUsuarioDao usuarioDao; //inyectado de interface
	
	private Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class);
	
	@Override//sobreEscribo
	@Transactional(readOnly=true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				//logger.info("username " + username);
        Usuario usuario = usuarioDao.findByUsername(username);//buscamos
				logger.info("username " + username);
        
        if(usuario == null) {
        	logger.error("Error en el Login: no existe el usuario '" + username + "' en el sistema!");
        	throw new UsernameNotFoundException("Username: " + username + " no existe en el sistema!");
        }
        
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();//lista de roles porque viene muchos
        
        for(Role role: usuario.getRoles()) {
        	logger.info("Role: ".concat(role.getAuthority()));
        	authorities.add(new SimpleGrantedAuthority(role.getAuthority()));//añadimos el role
        }
        
        if(authorities.isEmpty()) {
        	logger.error("Error en el Login: Usuario '" + username + "' no tiene roles asignados!");
        	throw new UsernameNotFoundException("Error en el Login: usuario '" + username + "' no tiene roles asignados!");
        }
        //return 
		return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true, authorities);
	}

}
