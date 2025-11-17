package com.joaodev.hr_user.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.joaodev.hr_user.entities.User;

public interface UserReository extends JpaRepository<User, Long> {

    User findByEmail(String email);
}
