package com.hireconnect.auth.repository;

import com.hireconnect.auth.pojo.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface AuthRepository extends JpaRepository<UserCredential, Integer> {

    Optional<UserCredential> findByEmail(String email);

    boolean existsByEmail(String email);

    void deleteByUserId(int userId);
}