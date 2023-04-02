package com.aflac.everwell.authentication.service;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.aflac.everwell.authentication.models.MyUserDetails;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtTokenGeneratorServiceImpl implements JwtTokenGeneratorService {

	@Value("${jwt.secret}")
	private String secret;

	@Override
	public String generateToken(MyUserDetails user) {
		return Jwts.builder().setSubject(user.getUsername()).setIssuedAt(new Date())
				.signWith(SignatureAlgorithm.HS256, "secret").compact();
	}

}
