package com.debuggeandoideas.app_security.Security;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.debuggeandoideas.app_security.Repository.UsuarioRepository;

import jakarta.transaction.Transactional;

@Component
@Transactional
public class MyAuthenticationProvider implements AuthenticationProvider{

	private UsuarioRepository usuarioRepository;
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	public MyAuthenticationProvider(UsuarioRepository usuarioRepository) {
		super();
		this.usuarioRepository = usuarioRepository;
	}
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		final var username = authentication.getName();
		final var password = authentication.getCredentials().toString();
		//final var userFromDb = this.usuarioRepository.findByEmail(username);
		final var userFromDb = this.usuarioRepository.GET_USER_BY_USERNAME(username, 1);
		final var user = userFromDb.orElseThrow(()-> new BadCredentialsException("Invalid Credentials"));
		final var userPwd = user.getPass();
		if(passwordEncoder.matches(password, userPwd)) {
			//final var roles = user.getRol();
			final var authorities = List.of(new SimpleGrantedAuthority(user.getRol()));
			return new UsernamePasswordAuthenticationToken(username, userPwd, authorities);
		}else {
			throw new BadCredentialsException("Invalid credentials");
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
