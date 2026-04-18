package com.hireconnect.auth.controller;

import com.hireconnect.auth.pojo.UserCredential;
import com.hireconnect.auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    // POST /auth/register
    @PostMapping("/register")
    public ResponseEntity<UserCredential> register(@RequestBody UserCredential credential) {
        return ResponseEntity.ok(authService.register(credential));
    }

    // POST /auth/login
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody Map<String, String> body) {
        String token = authService.login(body.get("email"), body.get("password"));
        return ResponseEntity.ok(token);
    }

    // POST /auth/logout
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String token) {
        authService.logout(token.replace("Bearer ", ""));
        return ResponseEntity.ok("Logged out successfully.");
    }

    // GET /auth/validate
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validate(@RequestParam String token) {
        return ResponseEntity.ok(authService.validateToken(token));
    }

    // GET /auth/refresh
    @GetMapping("/refresh")
    public ResponseEntity<String> refresh(@RequestParam String token) {
        return ResponseEntity.ok(authService.refreshToken(token));
    }
}