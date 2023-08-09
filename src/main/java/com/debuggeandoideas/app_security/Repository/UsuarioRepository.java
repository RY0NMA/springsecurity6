package com.debuggeandoideas.app_security.Repository;

import org.springframework.stereotype.Repository;

import com.debuggeandoideas.app_security.Entity.Usuario;

import java.util.Optional;

import org.springframework.data.jpa.repository.query.Procedure;
import org.springframework.data.repository.CrudRepository;

@Repository
public interface UsuarioRepository extends CrudRepository<Usuario, Integer>{

	Optional<Usuario> findByEmail(String email);
	
	@Procedure
	Optional<Usuario> GET_USER_BY_USERNAME(String username, int sistema);
}
