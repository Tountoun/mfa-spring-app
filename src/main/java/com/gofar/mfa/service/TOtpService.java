package com.gofar.mfa.service;

import com.gofar.mfa.dto.MfaSetupData;
import com.gofar.mfa.entity.User;
import com.gofar.mfa.repository.UserRepository;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class TOtpService {

    private UserRepository userRepository;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(32);
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.mfa.issuer}")
    private String issuer;
    @Value("${app.mfa.number-of-digits}")
    private int numberOfDigits;
    @Value("${app.mfa.period}")
    private int period;
    @Value("${app.mfa.scratch-codes-count}")
    private int scratchCodesCount;

    /**
     * Generate a new secret TOTP and the corresponding QR code
     * The MFA is not enabled yet, the user has to confirm via enableMfa by issuing a valid OTP
     * @param user the user to set up MFA for
     * @return the MFA setup data
     */
    public MfaSetupData setupMfa(User user) {
        String secret = this.secretGenerator.generate();

        user.setMfaSecret(secret);
        user.setMfaEnabled(false);
        user.setMfaVerified(false);
        this.userRepository.save(user);

        String otpAuthUrl = buildOtpAuthUrl(user.getUsername(), secret);
        String qrCodeBase64 = generateQrCodeBase64(otpAuthUrl);
        List<String> scratchCodes = generateScratchCodes(user);

        return MfaSetupData.builder()
                .secret(secret)
                .otpAuthUrl(otpAuthUrl)
                .qrCodeBase64(qrCodeBase64)
                .scratchCodes(scratchCodes)
                .build();
    }

    /**
     * Build the OTP Auth URL
     * Format otpauth://<type>/<label>?secret=<secret>&issuer=<issuer>&digits=<digits>&period=<period>&algorithm=<algorithm>
     * @param username the username
     * @param secret the secret
     * @return the OTP Auth URL
     */
    private String buildOtpAuthUrl(String username, String secret) {
        String label = URLEncoder.encode(issuer + ":" + username, StandardCharsets.UTF_8);
        String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8);

        return String.format(
                "otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d&algorithm=SHA1",
                label, secret, encodedIssuer, numberOfDigits, period
        );
    }

    /**
     * Generate the QR code base64
     * @param otpAuthUrl the OTP Auth URL
     * @return the QR code base64
     */
    private String generateQrCodeBase64(String otpAuthUrl) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(otpAuthUrl, BarcodeFormat.QR_CODE, 200, 200);

            ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", arrayOutputStream);

            return "data:image/png;base64," + Base64.getEncoder().encodeToString(arrayOutputStream.toByteArray());
        } catch (Exception e) {
            log.error("Error generating QR code", e);
            throw new RuntimeException("Error generating QR code", e);
        }
    }

    /**
     * Generate the scratch codes to be used in case the user loses his device
     * @param user the user
     * @return the scratch codes
     */
    private List<String> generateScratchCodes(User user) {
        List<String> scratchCodes = new ArrayList<>();
        for (int i = 0; i < scratchCodesCount; i++) {
            String scratchCode = generateRandomCode();
            scratchCodes.add(scratchCode);
        }
        user.setScratchCodes(String.join(",", scratchCodes));
        this.userRepository.save(user);
        return scratchCodes;
    }

    /**
     * Generate a random code
     * @return the random code
     */
    private String generateRandomCode() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == 4) {
                sb.append("-");
            }
            int index = this.secureRandom.nextInt(chars.length());
            sb.append(chars.charAt(index));
        }
        return sb.toString();
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}
