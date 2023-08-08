package com.debuggeandoideas.app_security.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
		/*/** quiere decir que todo lo que siga despues de los 2 puntos sea permitido*/
			auth.requestMatchers("/loans","/balance","/account","/cards").authenticated()
				.requestMatchers("/welcome","about").permitAll())//tambien pudo haber quedado como .anyRequest().permitAll())
			.formLogin(Customizer.withDefaults())
			.httpBasic(Customizer.withDefaults());
		return http.build();
		
	}
}
