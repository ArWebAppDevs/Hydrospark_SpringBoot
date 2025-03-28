package com.hydrospark.hydrospark.configuration;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Service;

import java.util.*;
import javax.mail.*;
import javax.mail.internet.*;

@Service
public class EmailService {
    public void sendEmail(HttpSession session,String email,String subject,String body) {
        String host = "smtpout.secureserver.net";
        final String username = "info@hydrospark.org"; // your email
        final String password = "Hydrospark@123";   // your email password

        // Recipient's email
        String to = email;
        System.out.println(to);

        // Set properties
        Properties properties = new Properties();
        properties.put("mail.smtp.host", host);
        properties.put("mail.smtp.port", "587");
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.starttls.enable", "true");

        // Get the default Session object
        Session sess = Session.getInstance(properties, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });

        try {
            // Create a default MimeMessage object
            MimeMessage message = new MimeMessage(sess);

            // Set From: header field
            message.setFrom(new InternetAddress(username));

            // Set To: header field
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));

            // Set Subject: header field
            message.setSubject(subject);

            // Set the actual message
            message.setText(body);

            // Send message
            Transport.send(message);

            System.out.println("Sent message successfully....");

        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}
