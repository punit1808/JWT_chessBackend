package com.chessmaster.Models;

public class blackKnight extends Piece {
    public blackKnight(String name, String color, int row, int col){
        super(name,color,row,col);
    }

    @Override
    public Boolean validMove(int or,int oc,int nr,int nc,Board board,User user){
        if(board.getPiece(nr, nc)!=null && board.getPiece(nr, nc).getColor().equals(user.getColor())) {
            return false; // cannot capture own piece
        }
        if((Math.abs(or-nr)==2 && Math.abs(oc-nc)==1) || (Math.abs(or-nr)==1 && Math.abs(oc-nc)==2)) {
            Piece destPiece = board.getPiece(nr, nc);
            if(destPiece!=null && destPiece.getColor().equals(user.getColor())) {
                return false;
            }
        }
        else {
            return false;
        }
        return true;
    }
}
