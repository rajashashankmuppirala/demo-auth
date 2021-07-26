package com.shashank.authservice.demoauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.Charset;
import java.util.*;

@Component
@Slf4j
public class CustomAuthentication implements AuthenticationProvider {

	public AccessTokenProvider userAccessTokenProvider() {
		ResourceOwnerPasswordAccessTokenProvider accessTokenProvider = new ResourceOwnerPasswordAccessTokenProvider();
		return accessTokenProvider;
	}

	@Autowired
	OktaConfig oktaConfig;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String userName = authentication.getPrincipal().toString();
		String password = authentication.getCredentials().toString();
		String url = "";
		String userDn = "";
		//User user =  userRepository.findByUsername(userName);
		//if(!user.isEnabled())
		//	throw new CustomOauthException("user disabled");
		//UserAuthenticationEntity userAuthEntity = userAuthRepository.findById(user.getId()).get();

		List<String> scopes = new ArrayList<String>();
		scopes.add("openid");

		String clientId = getClientId();
		if( null!= clientId && clientId.equals("cli")){

			final ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();

			resource.setUsername(userName);
			resource.setPassword(password);
			resource.setAccessTokenUri(oktaConfig.tokenUri);
			resource.setClientId(oktaConfig.clientId);
			resource.setClientSecret(oktaConfig.clientSecret);
			resource.setGrantType("password");
			resource.setScope(scopes);

			// Generate an access token
			final OAuth2RestTemplate template = new OAuth2RestTemplate(resource, new DefaultOAuth2ClientContext(new DefaultAccessTokenRequest()));
			template.setAccessTokenProvider(userAccessTokenProvider());

			OAuth2AccessToken accessToken = null;

			try {
				accessToken = template.getAccessToken();
				System.out.println("accessToken " + accessToken);
				Collection<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
				return new UsernamePasswordAuthenticationToken(userName, "N/A",authorities);

			}
			catch (OAuth2AccessDeniedException e) {
				if (e.getCause() instanceof ResourceAccessException) {
					final String errorMessage = String.format(
							"While authenticating user '%s': " + "Unable to access accessTokenUri '%s'.", userName,
							oktaConfig.tokenUri);
					throw new AuthenticationServiceException(errorMessage, e);
				}
				throw new BadCredentialsException(String.format("Access denied for user '%s'.", userName), e);
			}
			catch (OAuth2Exception e) {
				throw new AuthenticationServiceException(
						String.format("Unable to perform OAuth authentication for user '%s'.", userName), e);
			}

		}



		Collection<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
		/*if(null != user) {
			if(!CollectionUtils.isEmpty(user.getAuthorities())) {
				user.getAuthorities().forEach(authority ->
				authorities.add(new SimpleGrantedAuthority(authority.getAuthority())));
			}else
			{
				authorities.add(new SimpleGrantedAuthority("user"));
			}
		} */
		return new UsernamePasswordAuthenticationToken(userName, password,authorities);
	}

	 @Override
	    public boolean supports(Class<?> authentication) {
	        return authentication.equals(UsernamePasswordAuthenticationToken.class);
	    }

	private  String getClientId(){
		final HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();

		final String authorizationHeaderValue = request.getHeader("Authorization");
		final String base64AuthorizationHeader = Optional.ofNullable(authorizationHeaderValue)
				.map(headerValue->headerValue.substring("Basic ".length())).orElse("");

		if(null!= base64AuthorizationHeader && base64AuthorizationHeader.length() > 0){
			String decodedAuthorizationHeader = new String(Base64.getDecoder().decode(base64AuthorizationHeader), Charset.forName("UTF-8"));
			return decodedAuthorizationHeader.split(":")[0];
		}

		return "";
	}

}
