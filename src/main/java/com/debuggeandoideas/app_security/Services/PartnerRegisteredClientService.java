package com.debuggeandoideas.app_security.Services;

import java.time.Duration;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import com.debuggeandoideas.app_security.Repository.PartnerRepository;

@Service
public class PartnerRegisteredClientService implements RegisteredClientRepository{

	@Autowired
	private PartnerRepository partnerRepository;

	public PartnerRegisteredClientService(PartnerRepository partnerRepository) {
		super();
		this.partnerRepository = partnerRepository;
	}


	public PartnerRegisteredClientService() {
		super();
	}


	@Override
	public void save(RegisteredClient registeredClient) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public RegisteredClient findById(String id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		var partnerOpt  = this.partnerRepository.findByClientId(clientId);
		return partnerOpt.map(partner-> {
			var authorizationGrantTypes = Arrays.stream(partner.getGrantTypes().split(","))
					.map(AuthorizationGrantType:: new)
					.toList();
			
			var clientAuthenticationMethods = Arrays.stream(partner.getAuthenticateMethods().split(","))
					.map(ClientAuthenticationMethod:: new)
					.toList();
			
			var scopes = Arrays.stream(partner.getScopes().split(",")).toList();
			
			return RegisteredClient
					.withId(Integer.toString(partner.getIdPartner()))
					.clientId(partner.getClientId())
					.clientSecret(partner.getClientSecret())
					.clientName(partner.getClientName())
					.redirectUri(partner.getRedirectUri())
					.postLogoutRedirectUri(partner.getRedirectUriLogout())
					.clientAuthenticationMethod(clientAuthenticationMethods.get(0))
					.clientAuthenticationMethod(clientAuthenticationMethods.get(1))
					.scope(scopes.get(0))
					.scope(scopes.get(1))
					.authorizationGrantType(authorizationGrantTypes.get(0))
					.authorizationGrantType(authorizationGrantTypes.get(1))
					.tokenSettings(this.tokenSettings())
					.build();
		}).orElseThrow(() -> new BadCredentialsException("Client not exist"));
		/*
		return partnerOpt.map(partner-> {
			var authorizationGrantTypes = Arrays.stream(partner.getGrantTypes().split(","))
					.map(AuthorizationGrantType:: new)
					.toList();
			
			var clientAuthenticationMethods = Arrays.stream(partner.getAuthenticateMethods().split(","))
					.map(ClientAuthenticationMethod:: new)
					.toList();
			
			var scopes = Arrays.stream(partner.getScopes().split(",")).toList();
			
			return RegisteredClient
					.withId(Integer.toString(partner.getIdPartner()))
					.clientSecret(partner.getClientSecret())
					.clientName(partner.getClientName())
					.redirectUri(partner.getRedirectUri())
					.postLogoutRedirectUri(partner.getRedirectUriLogout())
					.clientAuthenticationMethod(clientAuthenticationMethods.get(0))
					.clientAuthenticationMethod(clientAuthenticationMethods.get(1))
					.scope(scopes.get(0))
					.scope(scopes.get(1))
					.authorizationGrantTypes(authorizationGrantTypes.get(0))
					.authorizationGrantTypes(authorizationGrantTypes.get(1))
					.tokenSettings(this.tokenSettings())
					.build();
		}).orElseThrow(() -> new BadCredentialsException("Client not exist"));
		*/
	}
	
	/* Duracion del Token*/
	private TokenSettings tokenSettings() {
		return TokenSettings.builder()
				//.accessTokenTimeToLive(Duration.ofHours(8))
				.accessTokenTimeToLive(Duration.ofMinutes(10))
				.build();
	}
	
}
