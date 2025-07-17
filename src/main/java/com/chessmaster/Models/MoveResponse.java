package com.chessmaster.Models;

public class MoveResponse {
    private Boolean isValid;
    private BoolResponse isSafe;
    private BoolResponse isWin;

    public MoveResponse(Boolean isValid, BoolResponse isSafe, BoolResponse isWin) {
        this.isValid = isValid;
        this.isSafe = isSafe;
        this.isWin = isWin;
    }

    public MoveResponse(){
        
    }

    public Boolean getIsValid() {
        return isValid;
    }

    public void setIsValid(Boolean isValid) {
        this.isValid = isValid;
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
