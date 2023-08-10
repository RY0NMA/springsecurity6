package com.debuggeandoideas.app_security.Security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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
		http.addFilterBefore(new ApiKeyFilter(), BasicAuthenticationFilter.class);
		var requestHandler = new CsrfTokenRequestAttributeHandler();
		requestHandler.setCsrfRequestAttributeName("_csrf");
		http.authorizeHttpRequests(auth ->
			//auth.requestMatchers("/loans","/balance","/account","/cards").hasAnyRole("ADMINISTRADOR","DESARROLLADOR","CONSULTOR")//para todos es authenticated
			auth.requestMatchers("/loans").hasAuthority("ADMINISTRADOR")
				.requestMatchers("/balance").hasAuthority("DESARROLLADOR")
				.requestMatchers("/accounts").hasAuthority("CONSULTOR")
				.requestMatchers("/cards").hasAnyAuthority("CONSULTOR","DESARROLLADOR")
				.requestMatchers("/welcome","about").permitAll())//tambien pudo haber quedado como .anyRequest().permitAll())
			.formLogin(Customizer.withDefaults())
			.httpBasic(Customizer.withDefaults())
			.cors(cors -> cors.configurationSource(corseConfigurationsSource())) // Aplica la configuración CORS
			.csrf(csrf -> csrf
					.csrfTokenRequestHandler(requestHandler)
					.ignoringRequestMatchers("/welcome","/about")
					.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
			.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
		/*Para eliminar errores del CORS*/
		//.cors(cors-> corseConfigurationsSource())
		//.csrf().disable();
		//http.csrf(AbstractHttpConfigurer::disable);
		//http.cors(cors-> corseConfigurationsSource());
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
	
	/*
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	*/
	
	@Bean
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }
	
	@Bean
	CorsConfigurationSource corseConfigurationsSource() {
		var config = new CorsConfiguration();
		//config.setAllowedOrigins(List.of("http://localhost:4200"));
		//config.setAllowCredentials(true);
		//config.setAllowedOriginPatterns(List.of("http://localhost:4200")); // Cambia "allowedOrigins" a "allowedOriginPatterns"
		config.setAllowedOrigins(List.of("*"));
		//config.setAllowedMethods(List.of("GET","POST","GET","DELETE"));
		config.setAllowedMethods(List.of("*"));
		config.setAllowedHeaders(List.of("*"));
		//config.setAllowedOrigins(List.of("*"));
		//config.setAllowCredentials(true);
		//config.setAllowedHeaders(List.of("Access-Control-Allow-Headers", "Access-Control-Allow-Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers", "Origin", "Cache-Control", "Content-Type", "Authorization"));
		//config.setAllowedMethods(List.of("DELETE", "GET", "POST", "PATCH", "PUT"));
		var source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}
}
