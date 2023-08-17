package com.debuggeandoideas.app_security.Controllers;

import java.util.Collections;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
//@CrossOrigin(origins = "http://localhost:4200")
public class WelcomeController {

	@GetMapping("/welcome")
	public Map<String, String> welcome(){
		return Collections.singletonMap("msj", "welcome");
		
	}
}
