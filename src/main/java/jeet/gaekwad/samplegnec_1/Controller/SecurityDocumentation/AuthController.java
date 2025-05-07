package jeet.gaekwad.samplegnec_1.Controller.SecurityDocumentation;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jeet.gaekwad.samplegnec_1.Security.JWT.JwtUtils;
import jeet.gaekwad.samplegnec_1.Security.LoginRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${app.cookie.domain:}")
    private String cookieDomain;

    @Value("${app.cookie.samesite:Lax}")
    private String cookieSameSite;

    public AuthController(JwtUtils jwtUtils, UserDetailsService userDetailsService) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder();
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        // Step 1: Authenticate user
        UserDetails user = userDetailsService.loadUserByUsername(request.getUsername());
        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            throw new BadCredentialsException("This user uses OAuth login. Password login is not available.");
        }
        if (!bCryptPasswordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        // Step 2: Generate tokens
        String accessToken = jwtUtils.generateToken(user.getUsername(), 15); // 15 minutes
        String refreshToken = jwtUtils.generateToken(user.getUsername(), 7 * 24 * 60); // 7 days

        // Step 3: Set tokens as HttpOnly cookies
        setAuthCookies(response, accessToken, refreshToken);

        logger.info("Login successful for user: {}", request.getUsername());
        return ResponseEntity.ok().body(Map.of(
                "success", true,
                "message", "Login successful. Tokens set in cookies."
        ));
    }

    private void setAuthCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Access token cookie
        Cookie accessTokenCookie = new Cookie("auth_token", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(cookieSecure);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(15 * 60);
        System.out.println("Auth token is here ");// 15 minutes

        if (!cookieDomain.isEmpty()) {
            accessTokenCookie.setDomain(cookieDomain);
        }

        // Apply SameSite attribute via header since Jakarta Cookie doesn't support it directly
        String accessCookieHeader = String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; %sSameSite=%s",
                accessTokenCookie.getName(),
                accessTokenCookie.getValue(),
                accessTokenCookie.getMaxAge(),
                cookieSecure ? "Secure; " : "",
                cookieSameSite);

        response.addHeader("Set-Cookie", accessCookieHeader);

        // Refresh token cookie
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(cookieSecure);
        refreshTokenCookie.setPath("/api/auth/refresh"); // Path limited to refresh endpoint
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days

        if (!cookieDomain.isEmpty()) {
            refreshTokenCookie.setDomain(cookieDomain);
        }

        // Apply SameSite attribute via header
        String refreshCookieHeader = String.format("%s=%s; Max-Age=%d; Path=/api/auth/refresh; HttpOnly; %sSameSite=%s",
                refreshTokenCookie.getName(),
                refreshTokenCookie.getValue(),
                refreshTokenCookie.getMaxAge(),
                cookieSecure ? "Secure; " : "",
                cookieSameSite);

        response.addHeader("Set-Cookie", refreshCookieHeader);

        logger.debug("Auth cookies set with domain: {}, secure: {}, samesite: {}",
                cookieDomain.isEmpty() ? "default" : cookieDomain, cookieSecure, cookieSameSite);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            @CookieValue(name = "refresh_token", required = false) String refreshToken,
            HttpServletResponse response) {

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "No refresh token provided"
            ));
        }

        try {
            // Use your combined method
            String username = jwtUtils.validateAndExtractUsername(refreshToken);

            if (username != null) {
                String newAccessToken = jwtUtils.generateToken(username, 15); // 15 minutes

                // Set the new access token cookie
                Cookie accessTokenCookie = new Cookie("auth_token", newAccessToken);
                accessTokenCookie.setHttpOnly(true);
                accessTokenCookie.setSecure(cookieSecure);
                accessTokenCookie.setPath("/");
                accessTokenCookie.setMaxAge(15 * 60);
                System.out.println("Refresh token: " + refreshToken + "is here for user: " + username);

                if (!cookieDomain.isEmpty()) {
                    accessTokenCookie.setDomain(cookieDomain);
                }

                String accessCookieHeader = String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; %sSameSite=%s",
                        accessTokenCookie.getName(),
                        accessTokenCookie.getValue(),
                        accessTokenCookie.getMaxAge(),
                        cookieSecure ? "Secure; " : "",
                        cookieSameSite);

                response.addHeader("Set-Cookie", accessCookieHeader);

                logger.info("Token refreshed for user: {}", username);
                return ResponseEntity.ok().body(Map.of(
                        "success", true,
                        "message", "Token refreshed successfully"
                ));
            }

            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Invalid refresh token"
            ));

        } catch (Exception e) {
            logger.error("Error refreshing token: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Error refreshing token"
            ));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        // Clear auth cookies by setting their max age to 0
        Cookie accessTokenCookie = new Cookie("auth_token", "");
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(cookieSecure);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);

        Cookie refreshTokenCookie = new Cookie("refresh_token", "");
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(cookieSecure);
        refreshTokenCookie.setPath("/api/auth/refresh");
        refreshTokenCookie.setMaxAge(0);

        if (!cookieDomain.isEmpty()) {
            accessTokenCookie.setDomain(cookieDomain);
            refreshTokenCookie.setDomain(cookieDomain);
        }

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);

        logger.info("User logged out successfully");
        return ResponseEntity.ok().body(Map.of(
                "success", true,
                "message", "Logged out successfully"
        ));
    }
}