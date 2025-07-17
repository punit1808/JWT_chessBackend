package com.chessmaster.Models;

public class SocketResponse {
    private Board board;
    private String turn;
    private BoolResponse isSafe;
    private BoolResponse isWin;

    public SocketResponse(){

    }

    public SocketResponse(Board board, String turn, BoolResponse isSafe, BoolResponse isWin) {
        this.board = board;
        this.turn = turn;
        this.isSafe = isSafe;
        this.isWin = isWin;
    }

    public Board getBoard() {
        return board;
    }

    public void setBoard(Board board) {
        this.board = board;
    }

    public String getTurn() {
        return turn;
    }

    public void setTurn(String turn) {
        this.turn = turn;
    }

    public BoolResponse getIsSafe() {
        return isSafe;
    }

    public void setIsSafe(BoolResponse isSafe) {
        this.isSafe = isSafe;
    }

    public BoolResponse getIsWin() {
        return isWin;
    }

    public void setIsWin(BoolResponse isWin) {
        this.isWin = isWin;
    }

    


}
