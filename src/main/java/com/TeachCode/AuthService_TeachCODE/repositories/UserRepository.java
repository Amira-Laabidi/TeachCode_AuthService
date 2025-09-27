package com.TeachCode.AuthService_TeachCODE.repositories;

import com.TeachCode.AuthService_TeachCODE.entities.Role;
import com.TeachCode.AuthService_TeachCODE.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {


    // Correct method to find users by role
    List<User> findAllByRolesContaining(Role role);

    // Find user by email
    Optional<User> findByEmail(String email);
}
