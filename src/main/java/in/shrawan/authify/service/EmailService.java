package in.shrawan.authify.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;


    @Value("${spring.mail.properties.mail.smtp.from}")
    private String fromEmail;

    public void sendWelcomeEmail(String toEmail, String name) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Welcome to Authify");
        message.setText("Hello " + name + ",\n\nThank you for registering.\n\nBest regards,\nAuthify Team");
        mailSender.send(message);
    }

    public void sendResetOtpEmail(String toEmail, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Password Reset OTP");
        message.setText("Hello,\n\nYour OTP for password reset is: " + otp + "\n\nBest regards,\nAuthify Team");
        mailSender.send(message);


    }

    public void sendOtpEmail(String toEmail, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("OTP for Authentication");
        message.setText("Hello,\n\nYour OTP for authentication is: " + otp + "\n\nBest regards,\nAuthify Team");
        mailSender.send(message);
    }





}
