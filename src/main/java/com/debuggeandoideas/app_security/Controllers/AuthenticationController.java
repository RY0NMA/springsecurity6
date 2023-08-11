package com.debuggeandoideas.app_security.Controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.debuggeandoideas.app_security.Entity.JWTRequest;
import com.debuggeandoideas.app_security.Entity.JWTResponse;
import com.debuggeandoideas.app_security.Security.JwtUserDetailService;
import com.debuggeandoideas.app_security.Services.JWTService;

@RestController
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final JwtUserDetailService jwtUserDetailService;
    private final JWTService jwtService;
    
    

    public AuthenticationController(AuthenticationManager authenticationManager,
			JwtUserDetailService jwtUserDetailService, JWTService jwtService) {
		super();
		this.authenticationManager = authenticationManager;
		this.jwtUserDetailService = jwtUserDetailService;
		this.jwtService = jwtService;
	}

	@PostMapping("/authenticate")
    public ResponseEntity<?> postToken(@RequestBody JWTRequest request) {
        this.authenticate(request);

        final var userDetails = this.jwtUserDetailService.loadUserByUsername(request.getUsername());

        final var token = this.jwtService.generateToken(userDetails);
        return ResponseEntity.ok(new JWTResponse(token));
    }

    private void authenticate(JWTRequest request) {
        try {
            this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        } catch (BadCredentialsException | DisabledException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}