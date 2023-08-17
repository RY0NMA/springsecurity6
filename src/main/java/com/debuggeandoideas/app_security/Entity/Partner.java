package com.debuggeandoideas.app_security.Entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name="PARTNER")
public class Partner {
	
	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	@Column(name="ID_PARTNER")
	public int idPartner;
	@Column(name="CLIENT_ID")
	public String clientId;
	@Column(name="CLIENT_NAME")
	public String clientName;
	@Column(name="CLIENT_SECRET")
	public String clientSecret;
	@Column(name="SCOPES")
	public String scopes;
	@Column(name="GRANT_TYPES")
	public String grantTypes;
	@Column(name="AUTHENTICATE_METHODS")
	public String authenticateMethods;
	@Column(name="REDIRECT_URI")
	public String redirectUri;
	@Column(name="REDIRECT_URI_LOGOUT")
	public String redirectUriLogout;
	public Partner(int idPartner, String clientId, String clientName, String clientSecret, String scopes,
			String grantTypes, String authenticateMethods, String redirectUri, String redirectUriLogout) {
		super();
		this.idPartner = idPartner;
		this.clientId = clientId;
		this.clientName = clientName;
		this.clientSecret = clientSecret;
		this.scopes = scopes;
		this.grantTypes = grantTypes;
		this.authenticateMethods = authenticateMethods;
		this.redirectUri = redirectUri;
		this.redirectUriLogout = redirectUriLogout;
	}
	public Partner() {
		super();
	}
	public int getIdPartner() {
		return idPartner;
	}
	public void setIdPartner(int idPartner) {
		this.idPartner = idPartner;
	}
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	public String getClientName() {
		return clientName;
	}
	public void setClientName(String clientName) {
		this.clientName = clientName;
	}
	public String getClientSecret() {
		return clientSecret;
	}
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
	public String getScopes() {
		return scopes;
	}
	public void setScopes(String scopes) {
		this.scopes = scopes;
	}
	public String getGrantTypes() {
		return grantTypes;
	}
	public void setGrantTypes(String grantTypes) {
		this.grantTypes = grantTypes;
	}
	public String getAuthenticateMethods() {
		return authenticateMethods;
	}
	public void setAuthenticateMethods(String authenticateMethods) {
		this.authenticateMethods = authenticateMethods;
	}
	public String getRedirectUri() {
		return redirectUri;
	}
	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}
	public String getRedirectUriLogout() {
		return redirectUriLogout;
	}
	public void setRedirectUriLogout(String redirectUriLogout) {
		this.redirectUriLogout = redirectUriLogout;
	}
	@Override
	public String toString() {
		return "Partner [idPartner=" + idPartner + ", clientId=" + clientId + ", clientName=" + clientName
				+ ", clientSecret=" + clientSecret + ", scopes=" + scopes + ", grantTypes=" + grantTypes
				+ ", authenticateMethods=" + authenticateMethods + ", redirectUri=" + redirectUri
				+ ", redirectUriLogout=" + redirectUriLogout + "]";
	}	

}
