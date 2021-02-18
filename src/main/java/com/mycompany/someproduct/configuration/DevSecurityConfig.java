package com.mycompany.someproduct.configuration;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.AccessToken;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.context.WebApplicationContext;

@Configuration
@Slf4j
@Profile("local-dev")
public class DevSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.warn("Using configuration Dev Security Conf");

        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic();

        http.cors();

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/**");
    }

    @Bean
    @Scope(scopeName = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public AccessToken accessToken() {
        AccessToken accessToken = new AccessToken();
        accessToken.setSubject("abc");
        accessToken.setName("Tester");

        return accessToken;

    }
}
