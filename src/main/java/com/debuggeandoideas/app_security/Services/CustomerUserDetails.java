package com.debuggeandoideas.app_security.Services;


import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.debuggeandoideas.app_security.Repository.UsuarioRepository;
import com.debuggeandoideas.app_security.Security.CustomUser;

import jakarta.transaction.Transactional;

@Service
@Transactional
public class CustomerUserDetails implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    public CustomerUserDetails(UsuarioRepository usuarioRepository) {
		super();
		this.usuarioRepository = usuarioRepository;
	}

	@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.usuarioRepository.findByEmail(username)
                .map(customer -> {
                    final var roles = customer.getRoles();
                    final var authorities = roles
                            .stream()
                            .map(role -> new SimpleGrantedAuthority(role.getRol()))
                            .collect(Collectors.toList());
                    //return new User(customer.getEmail(), customer.getPass(), authorities); /*Asi funciona*/
                    return new CustomUser(customer.getEmail(), customer.getPass(), true, true,
                            true, true, authorities, "AQUI EL NOMBRE"); // Añade el campo "name"
                }).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}