package com.chessmaster.Repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.chessmaster.Models.User;

public interface UserRepo extends JpaRepository<User, String> {
    
}
