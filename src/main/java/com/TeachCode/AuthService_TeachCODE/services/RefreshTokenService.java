package com.TeachCode.AuthService_TeachCODE.services;

import com.TeachCode.AuthService_TeachCODE.entities.RefreshToken;
import com.TeachCode.AuthService_TeachCODE.entities.User;

import java.util.Optional;

public interface RefreshTokenService {


    public RefreshToken createRefreshToken(User user);
    public Optional<RefreshToken> findByToken(String token);
    public RefreshToken verifyExpiration(RefreshToken token);
    public void deleteByUser(User user);
}
