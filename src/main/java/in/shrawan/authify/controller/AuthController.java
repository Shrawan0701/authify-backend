package in.shrawan.authify.controller;


import in.shrawan.authify.io.AuthRequest;
import in.shrawan.authify.io.AuthResponse;
import in.shrawan.authify.io.ResetPasswordRequest;
import in.shrawan.authify.service.AppUserDetailsService;
import in.shrawan.authify.service.ProfileService;
import in.shrawan.authify.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1.0")
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final AppUserDetailsService appUserDetailsService;

    private final JwtUtil jwtUtil;

    private final ProfileService profileService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            authenticate(request.getEmail(), request.getPassword());
            final UserDetails userDetails = appUserDetailsService.loadUserByUsername(request.getEmail());
            final String jwtToken = jwtUtil.generateToken(userDetails);
            ResponseCookie cookie= ResponseCookie.from("jwt", jwtToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(Duration.ofDays(1))
                    .sameSite("Strict")
                    .build();
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(new AuthResponse(request.getEmail(),jwtToken));



        } catch (BadCredentialsException ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", true);
            error.put("message", "Invalid email or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        } catch (DisabledException ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", true);
            error.put("message", "Account is disabled");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
        }

    }

    private void authenticate(String email, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));

    }

    // in.shrawan.authify.controller.AuthController.java

    @GetMapping("/is-authenticated")
    private ResponseEntity<Boolean> isAuthenticated(@CurrentSecurityContext(expression = "authentication?.name") String email) {
        // If 'email' is null, it indicates no authentication object (rare, but good for safety).
        // If 'email' is "anonymousUser", it means the request is not authenticated.
        // Otherwise, it's an authenticated user's email.
        boolean authenticated = (email != null && !"anonymousUser".equals(email));
        return ResponseEntity.ok(authenticated);
    }

    @PostMapping("/send-reset-otp")
    public void sendResetOtp(@RequestParam String email) {
        try{
            profileService.sendResetOtp(email);

        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        }

    }

    @PostMapping("/reset-password")
    public void resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try{
            profileService.resetPassword(request.getEmail(), request.getOtp(), request.getNewPassword());

        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    @PostMapping("/send-otp") // This is the sendVerifyOtp method
    public void sendVerifyOtp(@RequestParam String email) { // <--- CHANGE HERE: Accept email directly
        try {
            // Now, 'email' will come from the frontend, not security context
            profileService.sendOtp(email);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    @PostMapping("/verify-otp")
    public void verifyEmail(@RequestBody Map<String, Object> request) { // <--- MODIFIED: ONLY take @RequestBody here
        // Extract both email and otp from the request body
        String email = (String) request.get("email"); // <--- GET EMAIL FROM REQUEST BODY
        String otp = (String) request.get("otp");     // <--- GET OTP FROM REQUEST BODY

        // Basic validation for presence
        if (email == null || email.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
        }
        if (otp == null || otp.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "OTP is required");
        }

        try {
            // Now, pass the email (from request body) to your service
            profileService.verifyOtp(email, otp);
        } catch (Exception e) {
            // Consider more specific exceptions from profileService for better error messages
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    @PostMapping("/logout")
                public ResponseEntity<?> logout(HttpServletResponse response) {
            ResponseCookie cookie = ResponseCookie.from("jwt", "")
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .maxAge(0)
                    .sameSite("Strict")
                    .build();

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body("Logged out successfully");

        }

    }









