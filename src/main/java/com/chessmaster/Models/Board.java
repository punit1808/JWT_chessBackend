package com.chessmaster.Models;

public class Board {

    int row=8;
    int col=8;

    private String gameId;
    private Piece[][] board;

    public Board(String gameId){
        this.gameId=gameId;
        this.board=new Piece[row][col];
        for(int i=0;i<row;i++){
            for(int j=0;j<col;j++){
                board[i][j]=null;
            }
        }

        Piece rookw1=new whiteRook("rook","white",0,0);
        board[0][0]=rookw1;
        Piece rookw2=new whiteRook("rook","white",0,7);
        board[0][7]=rookw2;
        Piece knightw1=new whiteKnight("knight","white",0,1);
        board[0][1]=knightw1;
        
        Piece knightw2=new whiteKnight("knight","white",0,6);
        board[0][6]=knightw2;
        Piece bishopw1=new whiteBishop("bishop","white",0,2);
        board[0][2]=bishopw1;

        Piece bishopw2=new whiteBishop("bishop","white",0,5);
        board[0][5]=bishopw2;
        Piece queenw=new whiteQueen("queen","white",0,3);
        board[0][3]=queenw;
        Piece kingw=new whiteKing("king","white",0,4);
        board[0][4]=kingw;
        Piece pawnw1=new whitePawn("pawn","white",1,0);
        board[1][0]=pawnw1;
        Piece pawnw2=new whitePawn("pawn","white",1,1); 
        board[1][1]=pawnw2;
        Piece pawnw3=new whitePawn("pawn","white",1,2);
        board[1][2]=pawnw3;
        Piece pawnw4=new whitePawn("pawn","white",1,3);
        board[1][3]=pawnw4;
        Piece pawnw5=new whitePawn("pawn","white",1,4);
        board[1][4]=pawnw5;
        Piece pawnw6=new whitePawn("pawn","white",1,5);
        board[1][5]=pawnw6;
        Piece pawnw7=new whitePawn("pawn","white",1,6);
        board[1][6]=pawnw7; 
        Piece pawnw8=new whitePawn("pawn","white",1,7);
        board[1][7]=pawnw8;

        Piece rookb1=new blackRook("rook","black",7,0);
        board[7][0]=rookb1;
        Piece rookb2=new blackRook("rook","black",7,7);
        board[7][7]=rookb2;
        Piece knightb1=new blackKnight("knight","black",7,1);
        board[7][1]=knightb1;
        Piece knightb2=new blackKnight("knight","black",7,6);
        board[7][6]=knightb2;
        Piece bishopb1=new blackBishop("bishop","black",7,2);
        board[7][2]=bishopb1;
        Piece bishopb2=new blackBishop("bishop","black",7,5);
        board[7][5]=bishopb2;
        Piece queenb=new blackQueen("queen","black",7,3);
        board[7][3]=queenb;
        Piece kingb=new blackKing("king","black",7,4);
        board[7][4]=kingb;
        Piece pawnb1=new blackPawn("pawn","black",6,0);
        board[6][0]=pawnb1;
        Piece pawnb2=new blackPawn("pawn","black",6,1);
        board[6][1]=pawnb2;
        Piece pawnb3=new blackPawn("pawn","black",6,2);
        board[6][2]=pawnb3;
        Piece pawnb4=new blackPawn("pawn","black",6,3);
        board[6][3]=pawnb4;
        Piece pawnb5=new blackPawn("pawn","black",6,4);
        board[6][4]=pawnb5;
        Piece pawnb6=new blackPawn("pawn","black",6,5);
        board[6][5]=pawnb6;
        Piece pawnb7=new blackPawn("pawn","black",6,6);
        board[6][6]=pawnb7;
        Piece pawnb8=new blackPawn("pawn","black",6,7);
        board[6][7]=pawnb8;

    }

    public Board(Board other) {
        this.row = other.row;
        this.col = other.col;
        this.gameId=other.gameId;
        this.board = new Piece[row][col];

        for (int i = 0; i < row; i++) {
            for (int j = 0; j < col; j++) {
                Piece originalPiece = other.board[i][j];
                if (originalPiece != null) {
                    this.board[i][j] = new Piece(
                        originalPiece.getName(),
                        originalPiece.getColor(),
                        originalPiece.getRow(),
                        originalPiece.getCol()
                    );
                } else {
                    this.board[i][j] = null;
                }
            }
        }
    }
 
    public Piece[][] getBoard() {
        return board;
    }
    

    public String getGameId() {
        return gameId;
    }

    public void setGameId(String gameId) {
        this.gameId = gameId;
    }

    public Piece getPiece(int row, int col) {
        return board[row][col];
    }
    
    public void setPiece(int row, int col, Piece piece) {
        if(piece!=null){
            board[piece.getRow()][piece.getCol()] = null;
            piece.setRow(row);
            piece.setCol(col);
            board[row][col] = piece;
        }
    }
}


