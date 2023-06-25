package com.dh.msbills.security;



import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity

public class OAuth2ResourceServerSecurityConfiguration {

//    @Bean
//    public KeyCloakJwtAuthenticationConverter keyCloakJwtAuthenticationConverter() {
//        return new KeyCloakJwtAuthenticationConverter();
//    }
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests()
//                .anyRequest().authenticated();
//        http.oauth2ResourceServer()
//                .jwt()
//                .jwtAuthenticationConverter(keyCloakJwtAuthenticationConverter());
//        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//        return http.build();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(new KeyCloakJwtAuthenticationConverter());
        http.cors().and().csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated();
        return http.build();
    }
    @Bean
    public JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/realms/parcial/protocol/openid-connect/certs").build();
    }

}

