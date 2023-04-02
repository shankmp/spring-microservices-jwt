package com.aflac.everwell.authentication.service;

import com.aflac.everwell.authentication.models.MyUserDetails;

public interface JwtTokenGeneratorService {
	
	String generateToken(MyUserDetails user);

}
