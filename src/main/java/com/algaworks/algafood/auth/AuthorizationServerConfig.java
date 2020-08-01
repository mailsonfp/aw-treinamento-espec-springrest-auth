package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailService;
	
	@Autowired
	private RedisConnectionFactory redisConnectionFactory;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write", "read")
				.accessTokenValiditySeconds(60 * 60 * 6) // 6 horas (padrão é 12 horas)
				.refreshTokenValiditySeconds(60 * 60 * 6)
			.and()
				.withClient("foodanalytics")
				.secret(passwordEncoder.encode("food123"))
				.authorizedGrantTypes("authorization_code")
				.scopes("write", "read")
				.redirectUris("http://aplicacao-cliente", "http://localhost:8082/authorization.html")
			.and()
				.withClient("faturamento")
				.secret(passwordEncoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("read")
			.and()
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("write", "read")
				.redirectUris("http://aplicacao-cliente")
			.and()
				.withClient("checktoken")
					.secret(passwordEncoder.encode("check123"));
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("isAuthenticated()");
//		security.checkTokenAccess("permitAll()");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailService)
			.tokenStore(redisTokenStore());
	}
	
	private TokenStore redisTokenStore() {
		return new RedisTokenStore(redisConnectionFactory);
		
	}
}
