package com.hireconnect.auth.pojo;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_credentials")
@Data
public class UserCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int userId;

    @Column(nullable = false, unique = true)
    private String email;

    private String passwordHash;

    private String role; // CANDIDATE or RECRUITER

    private String provider; // LOCAL or GITHUB

    private LocalDateTime createdAt = LocalDateTime.now();
}