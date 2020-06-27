package com.example.securityweb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalAuthentication
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				//.antMatchers("/**").permitAll()
				.antMatchers("/", "/home").permitAll()
				.antMatchers("/hello").hasAnyRole("USER", "ADMIN")
				.antMatchers("/admin").hasAnyRole("ADMIN")
				.anyRequest().authenticated()
				.and().httpBasic()
				// .and()
				// 	.formLogin()
				// 	.loginPage("/login")
				// 	.permitAll()
				.and()
					.logout()
					.permitAll();
	}

	// @Bean
	// @Override
	// public UserDetailsService userDetailsService() {
	// 	UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
	// 			.build();

	// 	return new InMemoryUserDetailsManager(user);
	// }

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		auth.inMemoryAuthentication()
				.withUser("test")
				.password(passwordEncoder().encode("test"))
				.roles("USER")
			.and()
				.withUser("admin")
				.password(passwordEncoder().encode("admin"))
				.roles("USER", "ADMIN");
	}
	
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }}