package jeet.gaekwad.samplegnec_1.Security.JWT.Filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jeet.gaekwad.samplegnec_1.Security.JWT.JwtUtils;
import jeet.gaekwad.samplegnec_1.Security.LoginRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Skip filter for non-login paths
        if (!request.getServletPath().equals("/api/auth/login")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Parse login request
            LoginRequest loginRequest = objectMapper.readValue(request.getReader(), LoginRequest.class);

            // Authenticate user
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
            );

            Authentication authResult = authenticationManager.authenticate(authentication);

            // Generate tokens only if authentication succeeds
            if (authResult.isAuthenticated()) {
                // Generate access token (15 minutes)
                String accessToken = jwtUtils.generateToken(authResult.getName(), 15);
                response.addHeader("Authorization", "Bearer " + accessToken);

                // Generate refresh token (7 days)
                String refreshToken = jwtUtils.generateToken(authResult.getName(), 7 * 24 * 60);

                // Send access token in cookie
                Cookie accessTokenCookie = new Cookie("access_token", accessToken);
                accessTokenCookie.setHttpOnly(true);
                accessTokenCookie.setSecure(true);
                accessTokenCookie.setPath("/");
                accessTokenCookie.setMaxAge(15 * 60);
                accessTokenCookie.setAttribute("SameSite", "Strict");
                response.addCookie(accessTokenCookie);

                // Secure cookie settings
                Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
                refreshTokenCookie.setHttpOnly(true);  // Prevent XSS
                refreshTokenCookie.setSecure(true);    // HTTPS only
                refreshTokenCookie.setPath("/api/auth/refresh-token"); // Only sent to refresh endpoint
                refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days in seconds
                refreshTokenCookie.setAttribute("SameSite", "Strict"); // CSRF protection

                response.addCookie(refreshTokenCookie);

                // Optional: Return user details in response
                response.setContentType("application/json");
                response.getWriter().write(objectMapper.writeValueAsString(
                        Map.of(
                                "message", "Login successful",
                                "accessToken", accessToken,
                                "expiresIn", 15 * 60 // seconds
                        )
                ));
            }

        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write(
                    objectMapper.writeValueAsString(
                            Map.of("error", "Authentication failed", "message", e.getMessage())
                    )
            );
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write(
                    objectMapper.writeValueAsString(
                            Map.of("error", "Internal server error", "message", e.getMessage())
                    )
            );
        }
    }
}