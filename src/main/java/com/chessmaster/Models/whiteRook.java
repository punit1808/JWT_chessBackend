package com.chessmaster.Models;

public class whiteRook extends Piece {
    public whiteRook(String name, String color, int row, int col){
        super(name,color,row,col);
    }

    @Override
    public Boolean validMove(int or,int oc,int nr,int nc,Board board,User user){
         if(board.getPiece(nr, nc)!=null && board.getPiece(nr, nc).getColor().equals(user.getColor())) {
            return false; // cannot capture own piece
        }
        if(or==nr){
            if(nc> oc){
                // check in right
                for(int i=oc+1;i<=nc;i++) {
                    if(board.getPiece(or, i)!=null && board.getPiece(or, i).getColor().equals(user.getColor())) {
                        return false;
                    }
                    else if(board.getPiece(or,i)!=null && board.getPiece(or,i).getColor().equals(user.getColor()) && i!=nc) {
                        return false;
                    }
                }
                // return true;
            }
            else{
                // check in left
                for(int i=nc;i<oc;i++) {
                    if(board.getPiece(or, i)!=null && board.getPiece(or, i).getColor().equals(user.getColor())) {
                        return false;
                    }
                    else if(board.getPiece(or,i)!=null && board.getPiece(or,i).getColor().equals(user.getColor()) && i!=nc) {
                        return false;
                    }
                }
                // return true;
            }
        }
        else if(oc==nc){
            if(nr> or){
                // check in down
                for(int i=or+1;i<=nr;i++) {
                    if(board.getPiece(i, oc)!=null && board.getPiece(i, oc).getColor().equals(user.getColor())) {
                        return false;
                    }
                    else if(board.getPiece(i,oc)!=null && board.getPiece(i,oc).getColor().equals(user.getColor()) && i!=nr) {
                        return false;
                    }
                }
                // return true;
            }
            else{
                // check in up
                for(int i=nr;i<or;i++) {
                    if(board.getPiece(i, oc)!=null && board.getPiece(i, oc).getColor().equals(user.getColor())) {
                        return false;
                    }
                    else if(board.getPiece(i,oc)!=null && board.getPiece(i,oc).getColor().equals(user.getColor()) && i!=nr) {
                        return false;
                    }
                }
                // return true;
            }
        }
        else{
            return false;
        }
        return true;
    }  
    
}
