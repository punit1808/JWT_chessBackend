package com.chessmaster.Models;

import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name="chess_games")
public class GameData {

    
    @Id
    private String gameId;
    private String player1Id;
    private String player2Id;

    private String winner=null;

    @OneToMany(mappedBy = "game", cascade = CascadeType.ALL)
    private List<State> moves;

    public GameData(){
       
    }

    public GameData(String gameId,String player1Id,String player2Id){
        this.gameId=gameId;
        this.player1Id=player1Id;
        this.player2Id=player2Id;
    }

    

    public String getGameId() {
        return gameId;
    }

    public void setGameId(String gameId) {
        this.gameId = gameId;
    }

    public String getPlayer1Id() {
        return player1Id;
    }

    public void setPlayer1Id(String player1Id) {
        this.player1Id = player1Id;
    }

    public String getPlayer2Id() {
        return player2Id;
    }

    public void setPlayer2Id(String player2Id) {
        this.player2Id = player2Id;
    }

    public List<State> getMoves() {
        return moves;
    }

    public void setMoves(List<State> moves) {
        this.moves = moves;
    }

    public String getWinner() {
        return winner;
    }

    public void setWinner(String winner) {
        this.winner = winner;
    }

}
