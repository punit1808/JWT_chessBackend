package com.chessmaster.Models;

public class blackQueen extends Piece{
    public blackQueen(String name, String color, int row, int col){
        super(name,color,row,col);
    }

    @Override
    public Boolean validMove(int or,int oc,int nr,int nc,Board board,User user){
        if(board.getPiece(nr, nc)!=null && board.getPiece(nr, nc).getColor().equals(user.getColor())) {
            return false; // cannot capture own piece
        }
        if(or==nr){
            if(nc> oc){
                for(int i=oc+1;i<=nc;i++) {
                    if(board.getPiece(or, i)!=null && board.getPiece(or, i).getColor().equals(user.getColor())) {
                        return false;
                    }
                    else if(board.getPiece(or,i)!=null && board.getPiece(or,i).getColor().equals(user.getColor()) && i!=nc) {
                        return false;
                    }
                }
            } else {
                for(int i=nc;i<oc;i++) {
                    if(board.getPiece(or, i)!=null && board.getPiece(or, i).getColor().equals(user.getColor())) {
                        return false;
                    }
                    else if(board.getPiece(or,i)!=null && board.getPiece(or,i).getColor().equals(user.getColor()) && i!=nc) {
                        return false;
                    }
                }
            }
        }
        else if(oc==nc){
            if(nr> or){
                for(int i=or+1;i<=nr;i++) {
                    if(board.getPiece(i, oc)!=null && board.getPiece(i, oc).getColor().equals(user.getColor())) {
                        return false;
                    }
                    else if(board.getPiece(i,oc)!=null && board.getPiece(i,oc).getColor().equals(user.getColor()) && i!=nr) {
                        return false;
                    }
                }
            } else {
                for(int i=nr;i<or;i++) {
                    if(board.getPiece(i, oc)!=null && board.getPiece(i, oc).getColor().equals(user.getColor())) {
                        return false;
                    }
                    else if(board.getPiece(i,oc)!=null && board.getPiece(i,oc).getColor().equals(user.getColor()) && i!=nr) {
                        return false;
                    }
                }
            }
        }
        else if(Math.abs(or-nr)==Math.abs(oc-nc)) {
            int rowStep = (nr > or) ? 1 : -1;
            int colStep = (nc > oc) ? 1 : -1;
            for(int i=or+rowStep, j=oc+colStep; i!=nr && j!=nc; i+=rowStep, j+=colStep) {
                if(board.getPiece(i, j)!=null && board.getPiece(i, j).getColor().equals(user.getColor())) {
                    return false;
                }
                else if(board.getPiece(i,j)!=null && board.getPiece(i,j).getColor().equals(user.getColor()) && i!=nr) {
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
