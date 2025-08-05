package in.shrawan.authify.filter;

import in.shrawan.authify.service.AppUserDetailsService;
import in.shrawan.authify.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j; 
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
@Slf4j 
public class JwtRequestFilter extends OncePerRequestFilter {

    private final AppUserDetailsService appUserDetailsService;
    private final JwtUtil jwtUtil;


    private static final List<String> PUBLIC_URLS = List.of(
            "/api/v1.0/login",
            "/api/v1.0/register",
            "/api/v1.0/send-reset-otp",
            "/api/v1.0/reset-password",
            "/api/v1.0/logout",
            "/api/v1.0/send-otp",
            "/api/v1.0/verify-otp",
            "/api/v1.0/verify-reset-otp"


    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getServletPath();
        log.debug("JWT Filter: Processing request for path: {}", path); 

        
        if (PUBLIC_URLS.contains(path)) {
            log.debug("JWT Filter: Path {} is public, skipping JWT validation.", path); 
            filterChain.doFilter(request, response);
            return; 
        }

        String jwt = null;
        String email = null;

        
        final String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            log.debug("JWT Filter: Found JWT in Authorization header."); 
        }

        
        if (jwt == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("jwt".equals(cookie.getName())) { 
                        jwt = cookie.getValue();
                        log.debug("JWT Filter: Found JWT in cookie named '{}'.", cookie.getName()); 
                        break;
                    }
                }
            } else {
                log.debug("JWT Filter: No cookies found in request."); 
            }
        } else {
            log.debug("JWT Filter: JWT already found in header, skipping cookie check."); 
        }

   
        if (jwt != null) {
            try {
              
                email = jwtUtil.extractEmail(jwt);
                log.debug("JWT Filter: Extracted email '{}' from JWT.", email);

                
                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.appUserDetailsService.loadUserByUsername(email);
                    log.debug("JWT Filter: Loaded UserDetails for email '{}'.", email); 

               
                    if (jwtUtil.validateToken(jwt, userDetails)) {
                        UsernamePasswordAuthenticationToken authenticationToken =
                                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                        log.debug("JWT Filter: Authentication set for user '{}'.", email); 
                    } else {
                        log.debug("JWT Filter: JWT validation failed for user '{}' (token invalid or expired).", email); 
                    }
                } else {
                    log.debug("JWT Filter: Email is null ({}) OR Authentication already exists (current: {}).", email, SecurityContextHolder.getContext().getAuthentication()); 
                }
            } catch (Exception e) {
               
                log.error("JWT Filter: Error during token extraction or validation: {}", e.getMessage(), e); 
            }
        } else {
            log.debug("JWT Filter: No JWT found, proceeding without authentication. Request to protected path will be denied if not authenticated."); 
        }

        filterChain.doFilter(request, response);
    }
}
