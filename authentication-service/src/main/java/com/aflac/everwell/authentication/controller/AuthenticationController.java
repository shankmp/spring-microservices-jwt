package com.aflac.everwell.authentication.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aflac.everwell.authentication.models.MyUserDetails;
import com.aflac.everwell.authentication.service.JwtTokenGeneratorService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
	
	@Autowired private JwtTokenGeneratorService jwtTokenGeneratorService;
		
	@PostMapping("/login")
	public ResponseEntity<?> login(Authentication authentication, HttpSession session, HttpServletRequest request, HttpServletResponse response) {
		if (authentication != null && authentication.isAuthenticated()) {
			session = !session.isNew() ? invalidateExistingSession(request, session) : session;
			MyUserDetails authenticatedUser = (MyUserDetails) authentication.getPrincipal();
			response.addHeader("token", jwtTokenGeneratorService.generateToken(authenticatedUser));
			return ResponseEntity.ok(new LoginResource(authenticatedUser));
		}
		return ResponseEntity.notFound().build();		
	}
	
	private HttpSession invalidateExistingSession(HttpServletRequest request, HttpSession session) {
        session.invalidate();
        return request.getSession(true);
    }
		
	@GetMapping("/roles")
    public ResponseEntity<?> getRoles(Authentication authentication) {
		if (authentication != null && authentication.isAuthenticated()) {
			MyUserDetails authenticatedUser = (MyUserDetails) authentication.getPrincipal();
			return ResponseEntity.ok(authenticatedUser.getAuthorities());
		}
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

}
