package com.chessmaster.Repo;

import com.chessmaster.Models.GameData;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GameEntityRepo extends JpaRepository<GameData, String> {
    Optional<GameData> findByGameId(String gameId);
}
