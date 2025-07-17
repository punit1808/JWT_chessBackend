package com.chessmaster.Models;

public class blackPawn extends Piece{
    public blackPawn(String name, String color, int row, int col){
        super(name,color,row,col);
    }

    @Override
    public Boolean validMove(int or,int oc,int nr,int nc,Board board,User user){
        if(board.getPiece(nr,nc)!=null && board.getPiece(nr, nc).getColor().equals(user.getColor())) {
            return false; // cannot capture own piece
        }
        if(or==6 && nr==4 && nc==oc) {
            Piece destPiece = board.getPiece(nr, nc);
            Piece destPiece0 = board.getPiece(or-1, nc);
            if(destPiece0!=null || destPiece!=null) {
                return false;
            }
        }
        else if(nr==or-1 && nc==oc) {
            Piece destPiece = board.getPiece(nr, nc);
            if(destPiece!=null) {
                return false;
            }
        }
        else if(nr==or-1 && Math.abs(oc-nc)==1) {
            Piece destPiece = board.getPiece(nr, nc);
            if(destPiece==null) {
                return false;
            }
            else if(destPiece.getColor().equals(user.getColor())) {
                return false;
            }
        }
        else {
            return false;
        }
        return true;
    }
    
}
