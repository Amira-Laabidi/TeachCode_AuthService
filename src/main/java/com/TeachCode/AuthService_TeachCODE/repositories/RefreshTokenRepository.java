package com.TeachCode.AuthService_TeachCODE.repositories;

import com.TeachCode.AuthService_TeachCODE.entities.RefreshToken;
import com.TeachCode.AuthService_TeachCODE.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {


    Optional<RefreshToken> findByUser(User user);
    Optional<RefreshToken> findByToken(String token);
    void deleteByUser(User user);
}
