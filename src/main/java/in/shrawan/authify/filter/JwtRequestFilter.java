package in.shrawan.authify.filter;

import in.shrawan.authify.service.AppUserDetailsService;
import in.shrawan.authify.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j; // <--- ADD THIS IMPORT
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@AllArgsConstructor
@Slf4j // <--- ADD THIS ANNOTATION
public class JwtRequestFilter extends OncePerRequestFilter {

    private final AppUserDetailsService appUserDetailsService;
    private final JwtUtil jwtUtil;

    // Ensure this list is up-to-date with all your public /api/v1.0/ endpoints
    private static final List<String> PUBLIC_URLS = List.of(
            "/api/v1.0/login",
            "/api/v1.0/register",
            "/api/v1.0/send-reset-otp",
            "/api/v1.0/reset-password",
            "/api/v1.0/logout",
            "/api/v1.0/send-otp",
            "/api/v1.0/verify-otp",
            "/api/v1.0/is-authenticated"

    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getServletPath();
        log.debug("JWT Filter: Processing request for path: {}", path); // <--- DEBUG LOG

        // Check if the current request path is a public URL
        if (PUBLIC_URLS.contains(path)) {
            log.debug("JWT Filter: Path {} is public, skipping JWT validation.", path); // <--- DEBUG LOG
            filterChain.doFilter(request, response);
            return; // Exit filter early for public URLs
        }

        String jwt = null;
        String email = null;

        // 1: Check Authorization header for Bearer token
        final String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            log.debug("JWT Filter: Found JWT in Authorization header."); // <--- DEBUG LOG
        }

        // 2: If not found in header, check cookies
        if (jwt == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("jwt".equals(cookie.getName())) { // Your cookie name is 'jwt'
                        jwt = cookie.getValue();
                        log.debug("JWT Filter: Found JWT in cookie named '{}'.", cookie.getName()); // <--- DEBUG LOG
                        break;
                    }
                }
            } else {
                log.debug("JWT Filter: No cookies found in request."); // <--- DEBUG LOG
            }
        } else {
            log.debug("JWT Filter: JWT already found in header, skipping cookie check."); // <--- DEBUG LOG
        }

        // 3: Validate token and set security context
        if (jwt != null) {
            try {
                // Extract email from JWT
                email = jwtUtil.extractEmail(jwt);
                log.debug("JWT Filter: Extracted email '{}' from JWT.", email); // <--- DEBUG LOG

                // If email extracted and no existing authentication in context
                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.appUserDetailsService.loadUserByUsername(email);
                    log.debug("JWT Filter: Loaded UserDetails for email '{}'.", email); // <--- DEBUG LOG

                    // Validate the token against user details
                    if (jwtUtil.validateToken(jwt, userDetails)) {
                        UsernamePasswordAuthenticationToken authenticationToken =
                                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                        log.debug("JWT Filter: Authentication set for user '{}'.", email); // <--- DEBUG LOG
                    } else {
                        log.debug("JWT Filter: JWT validation failed for user '{}' (token invalid or expired).", email); // <--- DEBUG LOG
                    }
                } else {
                    log.debug("JWT Filter: Email is null ({}) OR Authentication already exists (current: {}).", email, SecurityContextHolder.getContext().getAuthentication()); // <--- DEBUG LOG
                }
            } catch (Exception e) {
                // Catch any exception during token extraction or validation (e.g., SignatureException, ExpiredJwtException)
                log.error("JWT Filter: Error during token extraction or validation: {}", e.getMessage(), e); // <--- DEBUG LOG (with 'e' for stack trace)
            }
        } else {
            log.debug("JWT Filter: No JWT found, proceeding without authentication. Request to protected path will be denied if not authenticated."); // <--- DEBUG LOG
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}