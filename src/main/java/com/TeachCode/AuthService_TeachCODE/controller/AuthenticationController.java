package com.TeachCode.AuthService_TeachCODE.controller;
import com.TeachCode.AuthService_TeachCODE.Dto.request.ForgotPasswordRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.request.ResetPasswordRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.request.SignUpRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.request.SinginRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.response.JwtAuthenticationResponse;
import com.TeachCode.AuthService_TeachCODE.Exception.OTPExpiredException;
import com.TeachCode.AuthService_TeachCODE.Exception.TokenRefreshException;
import com.TeachCode.AuthService_TeachCODE.entities.RefreshToken;
import com.TeachCode.AuthService_TeachCODE.entities.User;
import com.TeachCode.AuthService_TeachCODE.services.AuthenticationService;
import com.TeachCode.AuthService_TeachCODE.services.RefreshTokenService;
import com.TeachCode.AuthService_TeachCODE.services.impl.JwtServiceImpl;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    private final RefreshTokenService refreshTokenService;

    private final JwtServiceImpl jwtService;

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthenticationResponse> signup(@RequestBody SignUpRequest request) {
        return ResponseEntity.ok(authenticationService.SignUp(request));
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthenticationResponse> signin(@RequestBody SinginRequest request, HttpServletResponse response) {
        JwtAuthenticationResponse jwtResponse = authenticationService.SignIn(request);

        if (jwtResponse != null && jwtResponse.getToken() != null) {
            // Set the token in the response header
            response.setHeader("Access-Control-Expose-Headers", "Authorization");
            response.setHeader("Access-Control-Allow-Headers", "Authorization, X-Pingother, Origin, X-Requested-with, " +
                    "Content-Type, Accept, X-Custom-header");
            response.setHeader("Authorization", "Bearer " + jwtResponse.getToken());
            // Return a response with user details in the body
            JSONObject responseBody = new JSONObject();
            responseBody.put("userID", jwtResponse.getUserId());
            responseBody.put("role", jwtResponse.getRole());
            return ResponseEntity.ok(jwtResponse);
        } else {
            return ResponseEntity.badRequest().body(jwtResponse); // Assuming jwtResponse can be null
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JwtAuthenticationResponse> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        RefreshToken token = refreshTokenService.findByToken(refreshToken).orElseThrow(
                () -> new TokenRefreshException(refreshToken, "Refresh token not found")
        );

        String newToken = jwtService.generateToken(token.getUser());

        return ResponseEntity.ok(JwtAuthenticationResponse.builder().token(newToken).refreshToken(refreshToken).build());
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        try {
            authenticationService.sendForgotPasswordEmail(request.getEmail());
            return ResponseEntity.ok("Password reset email sent successfully");
        } catch (OTPExpiredException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred");
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOTP(@RequestParam String email, @RequestParam String otp) {
        try {
            authenticationService.verifyOTP(email, otp); // Implement this method in your UserService
            return ResponseEntity.ok("OTP verified successfully");
        } catch (OTPExpiredException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("OTP verification failed: " + ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred");
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        try {
            authenticationService.resetPassword(request);
            return ResponseEntity.ok("Password reset successfully");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred");
        }
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(authenticationService.getAllUsers());
    }

    @GetMapping("/users/{id}")
//    @PreAuthorize("hasRole('ADMIN') or #id == principal.id")
    public ResponseEntity<User> getUserById(@PathVariable Integer id) {
        Optional<User> user = authenticationService.getUserById(id);
        return user.map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/user/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == principal.id")
    public ResponseEntity<User> updateUser(@PathVariable Integer id, @RequestBody User updatedUser) {
        return ResponseEntity.ok(authenticationService.updateUser(id, updatedUser));
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable Integer id) {
        authenticationService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

}

