package com.chessmaster.Models;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;


@Entity
@Table(name = "chess_state")
public class State {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private int oldRow;
    private int oldCol;
    private int newRow;
    private int newCol;
    private String color;
    private String pieceName;

    @ManyToOne
    @JoinColumn(name = "game_id")
    private GameData game;

    public State() {}

    public State(String pieceName,int oldRow, int oldCol, int newRow, int newCol, String color,GameData game) {
        this.oldRow = oldRow;
        this.newRow = newRow;
        this.oldCol = oldCol;
        this.newCol = newCol;
        this.color = color;
        this.pieceName = pieceName;
        this.game=game;
    }


    public Long getId() {
        return id;
    }

    public int getOldRow() {
        return oldRow;
    }

    public GameData getGame() {
        return game;
    }

    public void setGame(GameData game) {
        this.game = game;
    }

    public void setOldRow(int oldRow) {
        this.oldRow = oldRow;
    }

    public int getNewRow() {
        return newRow;
    }

    public void setNewRow(int newRow) {
        this.newRow = newRow;
    }

    public int getOldCol() {
        return oldCol;
    }

    public void setOldCol(int oldCol) {
        this.oldCol = oldCol;
    }

    public String getPieceName() {
        return pieceName;
    }

    public int getNewCol() {
        return newCol;
    }

    public void setPieceName(String pieceName) {
        this.pieceName = pieceName;
    }

    public void setNewCol(int newCol) {
        this.newCol = newCol;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }
}


