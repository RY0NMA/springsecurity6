package com.debuggeandoideas.app_security.Entity;

public class JWTResponse {

    private String jwt;

	public JWTResponse(String jwt) {
		super();
		this.jwt = jwt;
	}

	public JWTResponse() {
		super();
	}

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

	@Override
	public String toString() {
		return "JWTResponse [jwt=" + jwt + "]";
	}
    
}