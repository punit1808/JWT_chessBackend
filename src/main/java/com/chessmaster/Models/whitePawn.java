package com.chessmaster.Models;

public class whitePawn extends Piece {
    public whitePawn(String name, String color, int row, int col){
        super(name,color,row,col);
    }

    @Override
    public Boolean validMove(int or,int oc,int nr,int nc,Board board,User user){
        if(board.getPiece(nr,nc)!=null && board.getPiece(nr, nc).getColor().equals(user.getColor())) {
            return false; // cannot capture own piece
        }
        if(or==1 && nr==3 && nc==oc) {
            // check if the destination cell is empty or occupied by opponent's piece
            Piece destPiece = board.getPiece(nr, nc);
            Piece destPiece0 = board.getPiece(or+1, nc);
            if(destPiece0!=null || destPiece!=null) {
                return false;
            }
        }
        else if(nr==or+1 && nc==oc) {
            // check if the destination cell is empty or occupied by opponent's piece
            Piece destPiece = board.getPiece(nr, nc);
            if(destPiece!=null) {
                return false;
            }
        }
        else if(nr==or+1 && Math.abs(oc-nc)==1) {
            // check if the destination cell is empty or occupied by opponent's piece
            Piece destPiece = board.getPiece(nr, nc);
            if(destPiece==null) {
                return false;
            }
            else if(destPiece.getColor().equals(user.getColor())) {
                return false;
            }
        }
        else{
            return false;
        }
        return true;
    }
}
