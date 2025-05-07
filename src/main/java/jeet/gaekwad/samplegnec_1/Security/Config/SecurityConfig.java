package jeet.gaekwad.samplegnec_1.Security.Config;

import jeet.gaekwad.samplegnec_1.Security.JWT.Filter.JwtAuthenticationFilter;
import jeet.gaekwad.samplegnec_1.Security.JWT.Filter.JwtRefreshTokenFilter;
import jeet.gaekwad.samplegnec_1.Security.JWT.ProviderList.JwtAuthenticationProvider;
import jeet.gaekwad.samplegnec_1.Security.JWT.JwtUtils;
import jeet.gaekwad.samplegnec_1.Security.JWT.Filter.JwtValidationFilter;
import jeet.gaekwad.samplegnec_1.Security.Oauth.CustomOauthHandler;
import jeet.gaekwad.samplegnec_1.Service.AccountService.AccountServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private AccountServiceImpl accountService1;

    private UserDetailsService userDetailsService;
    private JwtUtils jwtUtils;
    private CustomOauthHandler customOAuthHandler;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService, JwtUtils jwtUtils , CustomOauthHandler customOAuthHandler) {
        this.userDetailsService = userDetailsService;
        this.jwtUtils = jwtUtils;
        this.customOAuthHandler = customOAuthHandler;
    }

   @Bean
    public PasswordEncoder passwordEncoder() { // For decoding and encoding the password
       return new BCryptPasswordEncoder();
   }

    @Bean
    public AuthenticationManager authenticationManager() { // custom authentication manager for list of providers
        return new ProviderManager(Arrays.asList(
                 daoAuthenticationProvider() //For checking the username and password
                ,jwtAuthenticationProvider() //For validating the Jwt token everytime
        ));
    }
    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider() { // custom JwtAuthentication provider for validating JWT
        return new JwtAuthenticationProvider(jwtUtils, accountService1);
    }
    @Bean
   public DaoAuthenticationProvider daoAuthenticationProvider() { // for validating the username and password from DB
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(accountService1);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
   }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Initialize your filters
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager(), jwtUtils);
        JwtValidationFilter jwtValidationFilter = new JwtValidationFilter(authenticationManager());
        JwtRefreshTokenFilter jwtRefreshTokenFilter = new JwtRefreshTokenFilter(jwtUtils, authenticationManager());

        http
                // Enable CORS and disable CSRF
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())

                // Authorization rules
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/login",
                                "/logout",
                                "/v1/register",
                                "/mimic3/tts",
                                "/api/auth/**",
                                "/oauth2/**",
                                "/login/**",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs.yaml",
                                "/error"
                        ).permitAll()
                        .requestMatchers("/v1/accounts").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

                // Session management
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // OAuth2 configuration
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(customOAuthHandler)
                )

                // JWT filters
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(jwtValidationFilter, JwtAuthenticationFilter.class)
                .addFilterAfter(jwtRefreshTokenFilter, JwtValidationFilter.class);

        return http.build();
    }

    // CORS Configuration Bean
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000")); // Your frontend URL
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
