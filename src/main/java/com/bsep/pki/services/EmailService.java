package com.bsep.pki.services;

import com.bsep.pki.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import com.bsep.pki.dtos.RegistrationDto;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private Environment env;

    @Async
    public void sendVerificationEmail(RegistrationDto registrationDto, String link) {
        try {
            MimeMessage mail = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mail, true);

            helper.setTo(registrationDto.getEmail());
            helper.setFrom(env.getProperty("spring.mail.username"));
            helper.setSubject("Verifikacija naloga - BSEP Aplikacija");

            String htmlMsg = "<p>Pozdrav " + registrationDto.getFirstName() + ",</p>"
                    + "<p>Klikni na link ispod kako bi izvršio verifikaciju svog naloga:</p>"
                    + "<a href='" + link + "'>Verifikuj svoj nalog</a>"
                    + "<p>Link važi 24 sata.</p>"
                    + "<p>Hvala!</p>";

            helper.setText(htmlMsg, true);
            System.out.println("Slanje emaila na: " + registrationDto.getEmail());
            javaMailSender.send(mail);
        } catch (MessagingException e) {
            System.err.println("Greška pri slanju emaila: " + e.getMessage());
            Thread.currentThread().interrupt();
        }
    }
    
    @Async
    public void sendPasswordResetEmail(User user, String link) {
        try {
            MimeMessage mail = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mail, true);

            helper.setTo(user.getEmail());
            helper.setFrom(env.getProperty("spring.mail.username"));
            helper.setSubject("Reset lozinke - BSEP Aplikacija");

            String htmlMsg = "<p>Pozdrav " + user.getFirstName() + ",</p>"
                    + "<p>Klikni na link ispod kako bi resetovao svoju lozinku:</p>"
                    + "<a href='" + link + "'>Resetuj lozinku</a>"
                    + "<p>Link važi 24 sata.</p>"
                    + "<p>Hvala!</p>";

            helper.setText(htmlMsg, true);
            System.out.println("Slanje emaila za reset lozinke na: " + user.getEmail());
            javaMailSender.send(mail);
        } catch (MessagingException e) {
            System.err.println("Greška pri slanju emaila za reset: " + e.getMessage());
            Thread.currentThread().interrupt();
        }
    }

    @Async
    public void sendInitialPasswordEmail(User user, String temporaryPassword) {
        try {
            MimeMessage mail = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mail, true);

            helper.setTo(user.getEmail());
            helper.setFrom(env.getProperty("spring.mail.username"));
            helper.setSubject("Privremena lozinka za CA korisnika - PKI Sistem");

            String htmlMsg = "<p>Pozdrav " + user.getFirstName() + ",</p>"
                    + "<p>Administrator je kreirao tvoj CA nalog.</p>"
                    + "<p>Privremena lozinka: <b>" + temporaryPassword + "</b></p>"
                    + "<p>Na prvom prijavljivanju moraš promeniti lozinku.</p>"
                    + "<p>Hvala!</p>";

            helper.setText(htmlMsg, true);
            javaMailSender.send(mail);
        } catch (MessagingException e) {
            Thread.currentThread().interrupt();
        }
    }
}
