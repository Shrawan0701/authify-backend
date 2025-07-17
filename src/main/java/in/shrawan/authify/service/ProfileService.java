package in.shrawan.authify.service;

import in.shrawan.authify.io.ProfileRequest;
import in.shrawan.authify.io.ProfileResponse;

public interface ProfileService {

    ProfileResponse createProfile(ProfileRequest request);

    ProfileResponse getProfile(String email);

    void sendResetOtp(String email);

    void resetPassword(String email, String otp, String password);

    void sendOtp(String email);

    void verifyOtp(String email, String otp);


}
