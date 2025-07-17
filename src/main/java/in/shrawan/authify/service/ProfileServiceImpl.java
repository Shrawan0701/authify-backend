package in.shrawan.authify.service;


import in.shrawan.authify.entity.UserEntity;
import in.shrawan.authify.io.ProfileRequest;
import in.shrawan.authify.io.ProfileResponse;
import in.shrawan.authify.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor

public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Override
    public ProfileResponse createProfile(ProfileRequest request) {
        UserEntity newProfile = convertToUserEntity(request);
        if (!userRepository.existsByEmail(request.getEmail())) {
            newProfile = userRepository.save(newProfile);
            return convertToProfileResponse(newProfile);
        }
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");

    }

    @Override
    public ProfileResponse getProfile(String email) {
          UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        return convertToProfileResponse(existingUser);
    }

    @Override
    public void sendResetOtp(String email) {
        UserEntity existingEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));

        long expiryTime = System.currentTimeMillis()+ (15 * 60 * 1000);

        existingEntity.setReset(otp);
        existingEntity.setResetOtpExpiredAt(expiryTime);
        userRepository.save(existingEntity);

        try{
            emailService.sendResetOtpEmail(existingEntity.getEmail(), otp);

        } catch (Exception ex) {
            throw new RuntimeException("Error sending email");
        }

    }

    @Override
    public void resetPassword(String email, String otp, String newPassword) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        if (existingUser.getReset()== null || !existingUser.getReset().equals(otp)) {
            throw new RuntimeException("Invalid Otp");
        }
        if (existingUser.getResetOtpExpiredAt() < System.currentTimeMillis()) {
            throw new RuntimeException("Otp expired");
        }

        existingUser.setPassword(passwordEncoder.encode(newPassword));
        existingUser.setReset(null);
        existingUser.setResetOtpExpiredAt(0L);


        userRepository.save(existingUser);


    }

    @Override
    public void sendOtp(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        if (existingUser.getIsAccountVerified() != null && existingUser.getIsAccountVerified()) {
            return;
        }
        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));

        long expiryTime = System.currentTimeMillis() + (24  * 60 * 60 * 1000);

        existingUser.setVerifyOtp(otp);
        existingUser.setVerifyOtpExpireAt(expiryTime);
        userRepository.save(existingUser);

        try {
            emailService.sendOtpEmail(existingUser.getEmail(), otp);
        } catch (Exception e) {
            throw new RuntimeException("Error sending email");
        }


    }

    @Override
    public void verifyOtp(String email, String otp) {
        UserEntity existingUser =userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        if (existingUser.getVerifyOtp() == null || !existingUser.getVerifyOtp().equals(otp)) {
            throw new RuntimeException("Invalid Otp");
        }
        if (existingUser.getVerifyOtpExpireAt() < System.currentTimeMillis()) {
            throw new RuntimeException("Otp expired");
        }

        existingUser.setIsAccountVerified(true);
        existingUser.setVerifyOtp(null);
        existingUser.setVerifyOtpExpireAt(0L);
        userRepository.save(existingUser);


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
                .resetOtpExpiredAt(0L)
                .verifyOtp(null)
                .verifyOtpExpireAt(0L)
                .resetOtpExpiredAt(null)
                .build();



    }
}
