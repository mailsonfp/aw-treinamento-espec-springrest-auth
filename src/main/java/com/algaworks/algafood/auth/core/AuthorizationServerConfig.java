package com.algaworks.algafood.auth.core;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	private final List<String> COMPLEMENTO_CHAVE = Arrays.asList("a","b","c","d","e","f","g","h","i","j","l","m","n","o","p","q","r","t","u","v","x","z","w","y","k");
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties; 
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("WRITE", "READ")
				.accessTokenValiditySeconds(60 * 60 * 6) // 6 horas (padrão é 12 horas)
				.refreshTokenValiditySeconds(60 * 60 * 6)
			.and()
				.withClient("foodanalytics")
				.secret(passwordEncoder.encode("food123"))
				.authorizedGrantTypes("authorization_code")
				.scopes("WRITE", "READ")
				.redirectUris("http://aplicacao-cliente", "http://localhost:8082/authorization.html")
			.and()
				.withClient("faturamento")
				.secret(passwordEncoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("READ")
			.and()
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("WRITE", "READ")
				.redirectUris("http://aplicacao-cliente")
			.and()
				.withClient("checktoken")
					.secret(passwordEncoder.encode("check123"));
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("isAuthenticated()")
				.tokenKeyAccess("permitAll()");
//		security.checkTokenAccess("permitAll()");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		
		var enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAcessTokenConverterKeyStore()));
		
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailService)
			.accessTokenConverter(jwtAcessTokenConverterKeyStore())
			.tokenEnhancer(enhancerChain)
			.approvalStore(approvalStore(endpoints.getTokenStore()));
	}
	
	private ApprovalStore approvalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		
		return approvalStore;
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAcessTokenConverterKeyStore() {
		var jwtAccessTokenConverter = new JwtAccessTokenConverter();
	    
	    var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
	    var keyStorePass = jwtKeyStoreProperties.getPassword();
	    var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
	    
	    var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
	    var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
	    
	    jwtAccessTokenConverter.setKeyPair(keyPair);
	    
	    return jwtAccessTokenConverter;
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAcessTokenConverter() {
		JwtAccessTokenConverter jwtAcessAccessTokenConverter = new JwtAccessTokenConverter();
		jwtAcessAccessTokenConverter.setSigningKey(montaChave("mailsonfp"));
		
		return jwtAcessAccessTokenConverter;
	}
	
	private String montaChave(String chaveInicial) {
		StringBuilder chaveRetorno = new StringBuilder(chaveInicial);
		
		COMPLEMENTO_CHAVE.forEach(l -> chaveRetorno.append(l));
				
		return chaveRetorno.toString();
	}
}
