package com.debuggeandoideas.app_security.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
	
	/*Authentication por default*/
	/*
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
		http.authorizeHttpRequests(auth ->
			auth.anyRequest().authenticated())
			.formLogin(Customizer.withDefaults())
			.httpBasic(Customizer.withDefaults());
		return http.build();
		
	}
	*/
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
		http.authorizeHttpRequests(auth ->
			auth.requestMatchers("/loans","/balance","/account","/cards").hasAnyRole("ADMINISTRADOR","DESARROLLADOR","CONSULTOR")//para todos es authenticated
				.requestMatchers("/welcome","about").permitAll())//tambien pudo haber quedado como .anyRequest().permitAll())
			.formLogin(Customizer.withDefaults())
			.httpBasic(Customizer.withDefaults());
		return http.build();
		
	}
	
	/*Para generar usuarios en Memoria*/
	/*
	@Bean
	InMemoryUserDetailsManager inMemoryUserDetailsManager() {
		UserDetails admin = User.withUsername("admin").password("to_be_encoded").authorities("ADMIN").build();
		UserDetails user = User.withUsername("user").password("to_be_encoded").authorities("USER").build();
		
		return new InMemoryUserDetailsManager(admin,user);
	}*/
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
}
