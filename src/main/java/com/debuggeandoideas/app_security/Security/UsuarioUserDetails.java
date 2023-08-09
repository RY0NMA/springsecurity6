package com.debuggeandoideas.app_security.Security;


import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.debuggeandoideas.app_security.Repository.UsuarioRepository;

import jakarta.transaction.Transactional;

@Service
@Transactional
public class UsuarioUserDetails implements UserDetailsService{

	private final UsuarioRepository usuarioRepository;
	
	public UsuarioUserDetails(UsuarioRepository usuarioRepository) {
		super();
		this.usuarioRepository = usuarioRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		//Optional<Usuario> user = usuarioRepository.GET_USER_BY_USERNAME(username, 1);
		/*
		Usuario aux = new Usuario();
		aux.setEmail("ricardo.lopez@hotmail.com");	
		aux.setEmpleado(1);
		aux.setIdRole(1);
		aux.setIdUser(1);
		aux.setName("RICARDO LOPEZ");
		aux.setPass("12345");
		aux.setRol("ADMINISTRADOR");
		aux.setUser("rlopez");
		Optional<Usuario> user = Optional.of(aux);
		if(user.isEmpty()) {
			throw new UsernameNotFoundException("User with email: " +username+" not found");
		}else {
			return new User(user.get().email,user.get().pass,List.of(new SimpleGrantedAuthority(user.get().rol)));
		}*/
		return this.usuarioRepository.GET_USER_BY_USERNAME(username, 1)
				.map(customer -> {
					var authorities = List.of(new SimpleGrantedAuthority("ROLE_"+customer.getRol()));
					return new User(customer.getEmail(), customer.getPass(), authorities);
				}).orElseThrow(()-> new UsernameNotFoundException("User not Found"));
	}

}
