package com.hireconnect.auth.service;

import com.hireconnect.auth.pojo.UserCredential;

public interface AuthService {

    UserCredential register(UserCredential credential);

    String login(String email, String password);

    void logout(String token);

    boolean validateToken(String token);

    String refreshToken(String token);

    UserCredential getByEmail(String email);
}