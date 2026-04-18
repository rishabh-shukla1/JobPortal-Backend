package com.hireconnect.auth.service;

import com.hireconnect.auth.pojo.UserCredential;
import com.hireconnect.auth.repository.AuthRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private AuthRepository authRepository;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiry}")
    private long tokenExpiry;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    @Override
    public UserCredential register(UserCredential credential) {
        if (authRepository.existsByEmail(credential.getEmail())) {
            throw new RuntimeException("Email already registered.");
        }
        credential.setPasswordHash(encoder.encode(credential.getPasswordHash()));
        if (credential.getProvider() == null) credential.setProvider("LOCAL");
        return authRepository.save(credential);
    }

    @Override
    public String login(String email, String password) {
        UserCredential user = authRepository.findByEmail(email)
            .orElseThrow(() -> new RuntimeException("User not found."));

        if (!encoder.matches(password, user.getPasswordHash())) {
            throw new RuntimeException("Invalid credentials.");
        }
        return generateToken(user);
    }

    private String generateToken(UserCredential user) {
        return Jwts.builder()
            .setSubject(user.getEmail())
            .claim("role", user.getRole())
            .claim("userId", user.getUserId())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + tokenExpiry))
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    @Override
    public String refreshToken(String token) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + tokenExpiry))
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    @Override
    public void logout(String token) {
        // Stateless JWT — client discards token.
        // Optional: add token to a Redis blacklist here later.
    }

    @Override
    public UserCredential getByEmail(String email) {
        return authRepository.findByEmail(email)
            .orElseThrow(() -> new RuntimeException("User not found."));
    }
}