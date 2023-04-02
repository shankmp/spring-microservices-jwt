package com.aflac.everwell.authentication.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.aflac.everwell.authentication.config.resource.ErrorResource;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired private ObjectMapper jacksonObjectMapper;
    //@Autowired private CustomBasicAuthenticationFilter customBasicAuthenticationFilter;
    
    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
        
    @Bean
    @Order(1)
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests
				//.requestMatchers("/auth/login").permitAll()
				//.requestMatchers("/currency-**").hasRole("ADMIN")
				.anyRequest().authenticated()
				// .requestMatchers("/user").hasAnyRole("ADMIN", "USER")
				//.requestMatchers("/").permitAll()
				).exceptionHandling(exception -> exception.accessDeniedHandler(accessDeniedHandler())
			               .authenticationEntryPoint(authenticationEntryPoint()))
				.csrf().disable()
            //.securityContext(securityContext -> securityContext
                    //.requireExplicitSave(false)  
                   // )
            //.addFilter(customBasicAuthenticationFilter)
            .logout().logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout"))
                     .logoutSuccessHandler(logoutSuccessHandler())
            .and()
            .formLogin().disable()
			.httpBasic();
		return http.build();
	}
    
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT);
    }
    
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new AuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response,
                    AuthenticationException authException) throws IOException, ServletException {
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                authenticationException(response, authException);
            }
        };
    }
    
    protected void authenticationException(HttpServletResponse response,
            AuthenticationException e) throws IOException {
        String message = e.getMessage();
        ErrorResource error = new ErrorResource(401, "notAuthorized", message);
        response.setStatus(401);
        jacksonObjectMapper.writeValue(response.getOutputStream(), error);
    }
    
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response,
                    AccessDeniedException accessDeniedException) throws IOException, ServletException {
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                forbiddenException(response, accessDeniedException);
            }
        };
    }
    
    protected void forbiddenException(HttpServletResponse response, AccessDeniedException e) throws IOException {
        
        ErrorResource error = new ErrorResource(HttpStatus.FORBIDDEN.value(), "Forbidden", e.getMessage());
        response.setStatus(error.getStatus());
        jacksonObjectMapper.writeValue(response.getOutputStream(), error);
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
