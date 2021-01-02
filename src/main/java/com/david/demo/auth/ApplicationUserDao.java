package com.david.demo.auth;

import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface ApplicationUserDao {
    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
