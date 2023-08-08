package com.debuggeandoideas.app_security.Controllers;

import java.util.Collections;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CardsController {
	
	@GetMapping("/cards")
	public Map<String, String> cards(){
		//..Logica
		return Collections.singletonMap("msj", "cards");
		
	}
}
