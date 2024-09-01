package ir.ac.kntu.hotelbookingapp.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import ir.ac.kntu.hotelbookingapp.security.user.HotelUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;


@Component
public class JwtUtils {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
	@Value("${auth.token.jwtSecret}")
	private              String jwtSecret;
	@Value("${auth.token.expirationInMills}")
	private              int    jwtExpirationTime;

	// This method used deprecated dependencies
//	public String generateJwtTokenForUser(Authentication authentication) {
//		HotelUserDetails userPrincipal = (HotelUserDetails) authentication.getPrincipal();
//		List<String> roles = userPrincipal.getAuthorities()
//				.stream()
//				.map(GrantedAuthority::getAuthority).toList();
//		return Jwts.builder().
//				setSubject(userPrincipal.getUsername())
//				.claim("roles", roles)
//				.issuedAt(new Date())
//				.setExpiration(new Date((new Date()).getTime() + jwtExpirationTime))
//				.signWith(key(), SignatureAlgorithm.HS256).compact();
//	}

//	public boolean validateToken(String token) {
//		try {
//			Jwts.parserBuilder().setSignKey(key()).build().parse(token);
//			return true;
//		} catch (MalformedJwtException e) {
//			logger.error("Invalid JWT token : {} ", e.getMessage());
//		} catch (ExpiredJWTExcpetion e) {
//			logger.error("Expired token : {} ", e.getMessage());
//		} catch (UnsupportedJWTException e) {
//			logger.error("This token is not supported : {}", e.getMessage());
//		} catch (IllegalArgumentException e) {
//			logger.error("No claims found : {}", e.getMessage());
//		}
//		return false;
//	}

	public boolean validateToken(String token) {
		try {
			JWTVerifier verifier = JWT.require(algorithm()).build();
			DecodedJWT  jwt      = verifier.verify(token);
			if (jwt.getExpiresAt().before(new Date())) {
				logger.error("Token has expired");
				return false;
			}
			return true;
		} catch (AlgorithmMismatchException e) {
			logger.error("Invalid JWT token: Algorithm mismatch - {}", e.getMessage());
		} catch (SignatureVerificationException e) {
			logger.error("Invalid JWT token: Invalid signature - {}", e.getMessage());
		} catch (TokenExpiredException e) {
			logger.error("Expired token: {}", e.getMessage());
		} catch (InvalidClaimException e) {
			logger.error("Invalid JWT token: Invalid claim - {}", e.getMessage());
		} catch (JWTDecodeException e) {
			logger.error("Invalid JWT token: Decoding error - {}", e.getMessage());
		} catch (JWTVerificationException e) {
			logger.error("Invalid JWT token : {} ", e.getMessage());
		}
		return false;
	}

	public String generateJwtTokenForUser(Authentication authentication) {
		HotelUserDetails userPrincipal = (HotelUserDetails) authentication.getPrincipal();
		List<String> roles = userPrincipal.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.toList();

		Instant now            = Instant.now();
		Instant expirationTime = now.plusMillis(jwtExpirationTime);

		return JWT.create()
				.withSubject(userPrincipal.getUsername())
				.withClaim("roles", roles)
				.withIssuedAt(Date.from(now))
				.withExpiresAt(Date.from(expirationTime))
				.sign(algorithm());
	}

	private Algorithm algorithm() {
		byte[] decodedSecret = Base64.getDecoder().decode(jwtSecret);
		return Algorithm.HMAC256(decodedSecret);
	}

	public String getUserNameFromToken(String token) {
		try {
			DecodedJWT jwt = JWT.require(algorithm())
					.build()
					.verify(token);
			return jwt.getSubject();
		} catch (JWTVerificationException e) {
			logger.error("Invalid JWT token has been received : {}", e.getMessage());
			return null;
		}
	}

//	priavte Key key() {
//		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
//	}
//
//	public String getUserNameFromToken(String token) {
//		return Jwts.parserBuilder()
//				.setSignKey(key())
//				.build()
//				.parseClaimsJws(token).getBody().getSubject();
//	}
}
