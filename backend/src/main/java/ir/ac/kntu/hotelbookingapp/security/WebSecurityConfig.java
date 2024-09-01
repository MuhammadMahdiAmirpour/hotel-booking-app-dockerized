package ir.ac.kntu.hotelbookingapp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.csrf(AbstractHttpConfigurer::disable)
				.cors(cors -> cors.configurationSource(corsConfigurationSource()))
				.authorizeHttpRequests(auth -> auth
						                               .requestMatchers("/**").permitAll()
				)
				.headers(headers -> headers
						                    .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
				);

		return http.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(List.of("*"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(Arrays.asList("authorization", "content-type", "x-auth-token"));
		configuration.setExposedHeaders(List.of("x-auth-token"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}
}

//@Configuration
//@EnableWebSecurity
//@RequiredArgsConstructor
//@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
//public class WebSecurityConfig {
//
//	private final HotelUserDetailsService userDetailsService;
//	private final JwtAuthEntryPoint       jwtAuthEntryPoint;
//
//	CorsConfig corsConfig;
//
//	@Autowired
//	public WebSecurityConfig(HotelUserDetailsService userDetailsService, JwtAuthEntryPoint jwtAuthEntryPoint,
//	                         CorsConfig corsConfig) {
//		this.userDetailsService = userDetailsService;
//		this.jwtAuthEntryPoint  = jwtAuthEntryPoint;
//		this.corsConfig         = corsConfig;
//	}
//
//	@Bean
//	public AuthTokenFilter authenticationTokenFilter() {
//		return new AuthTokenFilter();
//	}
//
//	@Bean
//	public DaoAuthenticationProvider authenticationProvider() {
//		var authProvider = new DaoAuthenticationProvider();
//		authProvider.setUserDetailsService(userDetailsService);
//		authProvider.setPasswordEncoder(passwordEncoder());
//		return authProvider;
//	}
//
//	@Bean
//	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
//		return authConfig.getAuthenticationManager();
//	}

//	@Bean
//	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//		http.csrf(AbstractHttpConfigurer::disable) // Disable CSRF for stateless API
//				.exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthEntryPoint))
//				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//				.authorizeHttpRequests(auth -> auth
//						                               .requestMatchers("/auth/**", "/rooms/**", "/bookings/**")
//						                               .permitAll()
//						                               .requestMatchers("/roles/**").hasRole("ADMIN")
//						                               .anyRequest().authenticated())
//				.cors(cors -> cors.configurationSource(corsConfig)); // Updated CORS configuration
////                .cors(AbstractHttpConfigurer::disable); // disable CORS configuration
//
//		http.authenticationProvider(authenticationProvider());
//		http.addFilterBefore(authenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);
//		return http.build();
//	}


//@Bean
//public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//	http.csrf(AbstractHttpConfigurer::disable)
//			.exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthEntryPoint))
//			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//			.authorizeHttpRequests(auth -> auth
//					                               .requestMatchers("/auth/**", "/rooms/**", "/bookings/**")
//					                               .permitAll()
//					                               .requestMatchers("/roles/**").hasRole("ADMIN")
//					                               .anyRequest().authenticated())
//			.cors(withDefaults()); // Use the default CORS configuration source
//
//	http.authenticationProvider(authenticationProvider());
//	http.addFilterBefore(authenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);
//	return http.build();
//}
//
//
//@Bean
//public PasswordEncoder passwordEncoder() {
//	return new BCryptPasswordEncoder();
//}

//	@Bean
//	public CorsConfigurationSource corsConfigurationSource() {
//		CorsConfiguration configuration = new CorsConfiguration();
//		configuration.setAllowedOrigins(List.of("http://localhost:80", "http://127.0.0.1:80")); // Use the service
//		// name for Docker
//		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//		configuration.setAllowedHeaders(List.of("*"));
//		configuration.setExposedHeaders(Arrays.asList("Authorization", "Content-Type"));
//		configuration.setAllowCredentials(true);
//		configuration.setMaxAge(3600L);
//		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//		source.registerCorsConfiguration("/**", configuration);
//		return source;
//	}

//	@Bean
//	public CorsConfigurationSource corsConfigurationSource() {
//		UrlBasedCorsConfigurationSource source        = new UrlBasedCorsConfigurationSource();
//		CorsConfiguration               configuration = new CorsConfiguration();
//		configuration.setAllowedOrigins(List.of("http://localhost:80", "http://127.0.0.1:80"));
//		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//		configuration.setAllowedHeaders(List.of("*"));
//		configuration.setExposedHeaders(Arrays.asList("Authorization", "Content-Type"));
//		configuration.setAllowCredentials(true);
//		configuration.setMaxAge(3600L);
//		source.registerCorsConfiguration("/**", configuration);
//		return source;
//	}
//
//}


