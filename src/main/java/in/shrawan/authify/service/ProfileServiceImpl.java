package in.shrawan.authify.service;

import in.shrawan.authify.entity.UserEntity;
import in.shrawan.authify.io.ProfileRequest;
import in.shrawan.authify.io.ProfileResponse;
import in.shrawan.authify.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
@Slf4j
public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Override
    public ProfileResponse createProfile(ProfileRequest request) {
        log.debug("ProfileService: Attempting to create profile for email: {}", request.getEmail());
        UserEntity newProfile = convertToUserEntity(request);
        if (!userRepository.existsByEmail(request.getEmail())) {
            // Generate OTP for verification
            String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));
            newProfile.setVerifyOtp(otp);
            newProfile.setVerifyOtpExpireAt(System.currentTimeMillis() + (60 * 60 * 1000)); // 15 minutes expiry

            newProfile = userRepository.save(newProfile); // Save user with OTP

            try {
                log.debug("ProfileService: Calling EmailService to send welcome/verification email to {}", newProfile.getEmail());

                emailService.sendWelcomeEmail(newProfile.getEmail(), newProfile.getName());

                emailService.sendOtpEmail(newProfile.getEmail(), otp);
            } catch (Exception e) {
                log.error("ProfileService: Failed to send welcome/verification email for {}. Error: {}", newProfile.getEmail(), e.getMessage(), e);

                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to send verification email.", e);
            }
            return convertToProfileResponse(newProfile);
        }
        log.warn("ProfileService: Email already exists: {}", request.getEmail());
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
    }

    @Override
    public ProfileResponse getProfile(String email) {
        log.debug("ProfileService: Fetching profile for email: {}", email);
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        return convertToProfileResponse(existingUser);
    }

    @Override
    public void sendResetOtp(String email) {
        log.debug("ProfileService: Request to send reset OTP for email: {}", email);
        UserEntity existingEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));
        long expiryTime = System.currentTimeMillis() + (15 * 60 * 1000); // 15 minutes expiry

        existingEntity.setReset(otp);
        existingEntity.setResetOtpExpiredAt(expiryTime);
        userRepository.save(existingEntity);

        try {
            log.debug("ProfileService: Calling EmailService to send password reset OTP email to {}", existingEntity.getEmail());
            emailService.sendResetOtpEmail(existingEntity.getEmail(), otp);
        } catch (Exception ex) {
            log.error("ProfileService: Failed to send password reset email for {}. Error: {}", existingEntity.getEmail(), ex.getMessage(), ex);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error sending password reset email.", ex);
        }
    }

    @Override
    public void resetPassword(String email, String otp, String newPassword) {
        log.debug("ProfileService: Attempting to reset password for email: {}", email);
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        if (existingUser.getReset() == null || !existingUser.getReset().equals(otp)) {
            log.warn("ProfileService: Invalid OTP provided for email: {}", email);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Otp");
        }
        if (existingUser.getResetOtpExpiredAt() < System.currentTimeMillis()) {
            log.warn("ProfileService: OTP expired for email: {}", email);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Otp expired");
        }

        existingUser.setPassword(passwordEncoder.encode(newPassword));
        existingUser.setReset(null);
        existingUser.setResetOtpExpiredAt(0L);
        userRepository.save(existingUser);
        log.info("ProfileService: Password reset successfully for email: {}", email);
    }

    @Override
    public void sendOtp(String email) { 
        log.debug("ProfileService: Request to resend verification OTP for email: {}", email);
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        if (existingUser.getIsAccountVerified() != null && existingUser.getIsAccountVerified()) {
            log.warn("ProfileService: User {} is already verified, not sending OTP.", email);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Account is already verified.");
        }
        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));
        long expiryTime = System.currentTimeMillis() + (15 * 60 * 1000);

        existingUser.setVerifyOtp(otp);
        existingUser.setVerifyOtpExpireAt(expiryTime);
        userRepository.save(existingUser);

        try {
            log.debug("ProfileService: Calling EmailService to send OTP email to {}", existingUser.getEmail());
            emailService.sendOtpEmail(existingUser.getEmail(), otp);
        } catch (Exception e) { 
            log.error("ProfileService: Failed to send OTP email for {}. Error: {}", existingUser.getEmail(), e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error sending email.", e);
        }
    }

    @Override
    public void verifyOtp(String email, String otp) {
        log.debug("ProfileService: Verifying OTP for email: {}", email);
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        if (existingUser.getVerifyOtp() == null || !existingUser.getVerifyOtp().equals(otp)) {
            log.warn("ProfileService: Invalid OTP provided for verification for email: {}", email);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Otp");
        }
        if (existingUser.getVerifyOtpExpireAt() == null || existingUser.getVerifyOtpExpireAt() < System.currentTimeMillis()) {
            log.warn("ProfileService: OTP expired for verification for email: {}", email);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Otp expired");
        }

        existingUser.setIsAccountVerified(true);
        existingUser.setVerifyOtp(null);
        existingUser.setVerifyOtpExpireAt(0L);
        userRepository.save(existingUser);
        log.info("ProfileService: Email verified successfully for: {}", email);
    }

    public void verifyResetOtp(String email, String otp) { 
        log.debug("ProfileService: Verifying RESET OTP for email: {}", email);
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

       
        if (existingUser.getReset() == null || !existingUser.getReset().equals(otp)) {
            log.warn("ProfileService: Invalid RESET OTP provided for email: {}", email);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Otp");
        }
      
        if (existingUser.getResetOtpExpiredAt() == null || existingUser.getResetOtpExpiredAt() < System.currentTimeMillis()) {
            log.warn("ProfileService: RESET OTP expired for email: {}", email);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Otp expired");
        }

        
        log.info("ProfileService: RESET OTP successfully verified for: {}", email);
    }

    private ProfileResponse convertToProfileResponse(UserEntity newProfile) {
        return ProfileResponse.builder()
                .name(newProfile.getName())
                .email(newProfile.getEmail())
                .userId(newProfile.getUserId())
                .isAccountVerified(newProfile.getIsAccountVerified())
                .build();
    }

    private UserEntity convertToUserEntity(ProfileRequest request) {
        return UserEntity.builder()
                .email(request.getEmail())
                .userId(UUID.randomUUID().toString())
                .name(request.getName())
                .password(passwordEncoder.encode(request.getPassword()))
                .isAccountVerified(false)
                .verifyOtp(null)
                .verifyOtpExpireAt(0L)
                .reset(null)
                .resetOtpExpiredAt(0L)
                .build();
    }
}
