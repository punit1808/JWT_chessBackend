package com.chessmaster.Repo;

import com.chessmaster.Models.State;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.List;

public interface StateRepo extends JpaRepository<State, Long> {

    List<State> findByGame_GameIdOrderByIdAsc(String gameId);
}
