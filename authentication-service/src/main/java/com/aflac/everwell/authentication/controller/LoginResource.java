package com.aflac.everwell.authentication.controller;

import com.aflac.everwell.authentication.models.MyUserDetails;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResource {
	
	private String username;
	
	public LoginResource(MyUserDetails authenticatedUser) {
		this.setUsername(authenticatedUser.getUsername());
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}
	
}
