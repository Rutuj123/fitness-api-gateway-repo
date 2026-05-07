package com.api.security;

import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
	
	private final String SECRET="MySuperSecretKeyForJwtWhichIsVerySecure12345";

	@Bean
public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
	http
	  .csrf(ServerHttpSecurity.CsrfSpec::disable)
	  .authorizeExchange(ex-> ex
			  .pathMatchers(HttpMethod.OPTIONS).permitAll()   // ⭐ IMPORTANT
	    		.pathMatchers("/auth/**").permitAll()
	    		.anyExchange().authenticated()
	    		)
	    .oauth2ResourceServer(oauth->oauth.jwt());
	return http.build();
}

@Bean
public ReactiveJwtDecoder jwtDecoder() {
    SecretKey key = new SecretKeySpec(
        SECRET.getBytes(),
        "HmacSHA256"
    );
    return NimbusReactiveJwtDecoder.withSecretKey(key).build();
}



}
