package com.debuggeandoideas.app_security.Controllers;

import java.util.Collections;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BalanceController {

	@GetMapping("/balance")
	public Map<String, String> balance(){
		//..Logica
		return Collections.singletonMap("msj", "balance");
		
	}
}
