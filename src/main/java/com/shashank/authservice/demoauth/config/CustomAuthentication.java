package com.shashank.authservice.demoauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import java.util.Collection;
import java.util.HashSet;

@Component
@Slf4j
public class CustomAuthentication implements AuthenticationProvider {


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

}
