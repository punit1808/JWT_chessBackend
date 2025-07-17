package com.chessmaster.Models;


public class Piece {
    
    private String name;
    private String color;
    private int row;
    private int col;

    public Piece() {

    }

    public Piece(String name, String color, int row, int col) {
        this.name = name;
        this.color = color;
        this.row = row;
        this.col = col;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public void setRow(int row) {
        this.row = row;
    }

    public void setCol(int col) {
        this.col = col;
    }

    public String getColor() {
        return color;
    }

    public int getRow() {
        return row;
    }

    public int getCol() {
        return col;
    }

    public Boolean validMove(int or,int oc,int nr,int nc,Board board,User user){
        return false;
    }

}


