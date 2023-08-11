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
public class JwtUserDetailService implements UserDetailsService{

	
	private final UsuarioRepository usuarioRepository;
	
	public JwtUserDetailService(UsuarioRepository usuarioRepository) {
		this.usuarioRepository = usuarioRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return this.usuarioRepository.GET_USER_BY_USERNAME(username, 1)
				.map(customer -> {
					var authorities = List.of(new SimpleGrantedAuthority(customer.getRol()));
					return new User(customer.getUser(), customer.getPass(), authorities);
				}).orElseThrow(()-> new UsernameNotFoundException("User not Found"));
	}

}
