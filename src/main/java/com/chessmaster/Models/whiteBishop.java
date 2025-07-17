package com.chessmaster.Models;

public class whiteBishop extends Piece {
    public whiteBishop(String name, String color, int row, int col){
        super(name,color,row,col);
    }

    @Override
    public Boolean validMove(int or,int oc,int nr,int nc,Board board,User user){
        if(board.getPiece(nr, nc)!=null && board.getPiece(nr, nc).getColor().equals(user.getColor())) {
            return false; // cannot capture own piece
        }
        if(Math.abs(or-nr)==Math.abs(oc-nc)) {
            // check in diagonal
            int rowStep = (nr > or) ? 1 : -1;
            int colStep = (nc > oc) ? 1 : -1;
            for(int i=or+rowStep, j=oc+colStep; i!=nr && j!=nc; i+=rowStep, j+=colStep) {
                if(board.getPiece(i, j)!=null) {
                    return false;
                }
            }
        }
        else{
            return false;
        }
        return true;
    }
    
}
