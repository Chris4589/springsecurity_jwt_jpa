package com.jwtexp.jwt_id.models.dao;
import com.jwtexp.jwt_id.models.Usuario;

import org.springframework.data.repository.CrudRepository;

public interface IUsuarioDao extends CrudRepository<Usuario, Long>{
	//@Query("SELECT u FROM users u WHERE u.username = :username")
	public Usuario findByUsername(String username);
}
