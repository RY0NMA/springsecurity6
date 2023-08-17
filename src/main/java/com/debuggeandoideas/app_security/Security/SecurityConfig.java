package com.debuggeandoideas.app_security.Security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.debuggeandoideas.app_security.Services.CustomerUserDetails;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;


@Configuration
public class SecurityConfig {
	
	@Bean
	@Order(1)
	SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception{
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
		.oidc(Customizer.withDefaults());
		http.exceptionHandling(e -> 
				e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_RESOURCE)));
		
		return http.build();
		
	}
	
	@Bean
    @Order(2)
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin(Customizer.withDefaults());
        http.authorizeHttpRequests(auth -> auth
        		//.requestMatchers(ADMIN_RESOURCES).hasAuthority(AUTH_WRITE)
        		//.requestMatchers(USER_RESOURCES).hasAuthority(AUTH_READ)
                .requestMatchers(ADMIN_RESOURCES).hasRole(ROLE_ADMIN)
                .requestMatchers(USER_RESOURCES).hasRole(ROLE_USER)
                .anyRequest().permitAll());
        http.oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));
        //http.sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(false);
        http.sessionManagement(session -> session
                .sessionConcurrency(configurer -> configurer
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false) // O true si deseas prevenir el inicio de sesión
                    )
                );
        return http.build();
    }
	
	@Bean
	BCryptPasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	}
	
	@Bean
    AuthenticationProvider authenticationProvider(BCryptPasswordEncoder encoder, CustomerUserDetails userDetails) {
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        authProvider.setUserDetailsService(userDetails);
        return authProvider;
    }
	 
	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
	    return AuthorizationServerSettings.builder().build();
	}
	/*
	@Bean
	JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter() {
		var converter = new JwtGrantedAuthoritiesConverter();
		converter.setAuthorityPrefix("");
		return converter;
	}
	*/
	
	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
	    var authConverter = new JwtGrantedAuthoritiesConverter();
	    authConverter.setAuthoritiesClaimName("roles");
	    authConverter.setAuthorityPrefix("");
	    var converterResponse = new JwtAuthenticationConverter();
	    converterResponse.setJwtGrantedAuthoritiesConverter(authConverter);
	    return converterResponse;
	}
	
	@Bean
	/*Este codifica el JWT*/
	JWKSource<SecurityContext> jwkSource() {
	    var rsa = generateKeys();
	    var jwkSet = new JWKSet(rsa);
	    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}
	
	@Bean
	/*Para Decodificar el JWT que viene en RSA*/
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
	    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
	/*Funciona sin problemas*/
	@Bean
    OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> {
            var authentication = context.getPrincipal();
            var authorities =  authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
            	LocalDateTime now = LocalDateTime.now();
                LocalDateTime expirationTime = now.plusMinutes(10);
                long iat = now.toEpochSecond(ZoneOffset.UTC);
                long exp = expirationTime.toEpochSecond(ZoneOffset.UTC);
                context.getClaims().claims(claim ->
                        claim.putAll(Map.of(
                                "roles", authorities,
                                "owner", APPLICATION_OWNER,
                                "name", authentication.getName(),
                                //"exp", exp, // Añadir tiempo de expiración
                                //"iat", iat,
                                "date_request", LocalDateTime.now().toString())));
                
            }
        };
    }
	
	/*Con este metodo se va a firmar el JWToken*/
	private static KeyPair generateRSA() {
        KeyPair keyPair;
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(RSA_SIZE);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        return keyPair;
    }
	
	/*Con este metodo generamos las Keys usando el metodo de generateRSA*/
	private static RSAKey generateKeys() {
        var keyPair = generateRSA();
        /*Generando la llave publica*/
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        /*Generando la llave privada*/
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();

    }
	
	private static final String[] USER_RESOURCES = {"/loans/**","/balance/**"};
    private static final String[] ADMIN_RESOURCES = {"/accounts/**","/cards/**"};
    private static final String AUTH_WRITE = "write";
    private static final String AUTH_READ = "read";
    private static final String ROLE_ADMIN = "ADMINISTRADOR";
    private static final String ROLE_USER = "DESARROLLADOR";
    private static final String LOGIN_RESOURCE = "/login";
    private static final String RSA = "RSA";
    private static final Integer RSA_SIZE = 2048;
    private static final String APPLICATION_OWNER = "Debuggeando ideas";
	
	/*
	@Bean
	RegisteredClientRepository clientRepository() {
		var client = RegisteredClient
				.withId(UUID.randomUUID().toString())
				.clientId("debbugeando ideas")
				.clientSecret("secret")
				.scope("read")
				.redirectUri("http://localhost:8080")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.build();
		return new InMemoryRegisteredClientRepository(client);
		
	}
	
	*/
}
