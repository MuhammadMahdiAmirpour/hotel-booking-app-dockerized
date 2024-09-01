package ir.ac.kntu.hotelbookingapp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

//@Configuration
//public class CorsConfig implements CorsConfigurationSource {
//
//    private static final Long MAX_AGE = 3600L;
//    private static final int CORS_FILTER_ORDER = -102;
//
//    @Bean
//    public FilterRegistrationBean<CorsFilter> corsFilter() {
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        CorsConfiguration config = new CorsConfiguration();
//
//        // Specify allowed origins
//        config.setAllowedOrigins(List.of("http://localhost:80", "http://127.0.0.1:80")); // Use the service name for
//        // Docker
//        config.setAllowCredentials(true);
//        config.setAllowedHeaders(List.of("*"));
//        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//        config.setMaxAge(MAX_AGE);
//
//        source.registerCorsConfiguration("/**", config);
//
//        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
//        bean.setOrder(CORS_FILTER_ORDER);
//        return bean;
//    }
//
//    @Override
//    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
//        CorsConfiguration config = new CorsConfiguration();
//        config.setAllowedOrigins(List.of("http://localhost:80", "http://127.0.0.1:80"));
//        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
//        config.setAllowedHeaders(List.of("*"));
//        return config;
//    }
//}
//

//@Configuration
//public class CorsConfig implements CorsConfigurationSource {
//
//	private static final Long MAX_AGE           = 3600L;
//	private static final int  CORS_FILTER_ORDER = -102;
//
//	@Bean
//	public FilterRegistrationBean<CorsFilter> corsFilter() {
//		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//		CorsConfiguration               config = new CorsConfiguration();
//
//		config.setAllowedOrigins(List.of("http://localhost:80", "http://127.0.0.1:80"));
//		config.setAllowCredentials(true);
//		config.setAllowedHeaders(List.of("*"));
//		config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//		config.setMaxAge(MAX_AGE);
//
//		source.registerCorsConfiguration("/**", config);
//
//		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
//		bean.setOrder(CORS_FILTER_ORDER);
//		return bean;
//	}
//
//	@Override
//	public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
//		CorsConfiguration config = new CorsConfiguration();
//		config.setAllowedOrigins(List.of("http://localhost:80", "http://127.0.0.1:80"));
//		config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
//		config.setAllowedHeaders(List.of("*"));
//		return config;
//	}
//}
//


@Configuration
public class CorsConfig {

	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();

		// Allow all origins
		config.addAllowedOrigin("*");

		// Allow all HTTP methods
		config.addAllowedMethod("*");

		// Allow all headers
		config.addAllowedHeader("*");

		// Allow credentials
		config.setAllowCredentials(true);

		source.registerCorsConfiguration("/**", config);
		return new CorsFilter(source);
	}
}


