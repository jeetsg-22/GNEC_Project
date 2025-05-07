package jeet.gaekwad.samplegnec_1.Security.Oauth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jeet.gaekwad.samplegnec_1.Model.Accounts;
import jeet.gaekwad.samplegnec_1.Repository.AccountRepository;
import jeet.gaekwad.samplegnec_1.Security.JWT.JwtUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import java.util.Map;

@Component
public class CustomOauthHandler implements AuthenticationSuccessHandler {

    @Autowired
    AccountRepository accountRepo;

    @Autowired
    JwtUtils jwtUtils;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        DefaultOAuth2User oAuthUser = (DefaultOAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuthUser.getAttributes();

        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");

        if (!accountRepo.findByEmail(email).isPresent()) {
            Accounts account = new Accounts();
            account.setEmail(email);
            account.setUsername(name);
            account.setRole("USER");
            accountRepo.save(account);
        }

        String jwtToken = jwtUtils.generateToken(name, 30);

        // Manual Set-Cookie header with SameSite
        String cookieHeader = String.format("JWT_TOKEN=%s; Max-Age=1800; Path=/; HttpOnly; Secure; SameSite=Lax", jwtToken);
        response.setHeader("Set-Cookie", cookieHeader);

        // Redirect to a static HTML page that closes the window
        response.sendRedirect("/oauth-success.html");
    }
}