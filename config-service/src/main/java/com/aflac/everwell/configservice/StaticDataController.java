package com.aflac.everwell.configservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StaticDataController {
	
	@GetMapping("/config")
	public String getConfig() {
		return "config";
	}

}
