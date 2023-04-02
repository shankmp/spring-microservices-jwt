package com.aflac.everwell.authentication.config;


import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aflac.everwell.authentication.models.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUserName(String userName);
}
