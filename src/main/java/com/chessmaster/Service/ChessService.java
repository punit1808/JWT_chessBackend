package com.chessmaster.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.chessmaster.Models.Board;
import com.chessmaster.Models.BoolResponse;
import com.chessmaster.Models.GameData;
import com.chessmaster.Models.Piece;
import com.chessmaster.Models.State;
import com.chessmaster.Models.User;
import com.chessmaster.Repo.StateRepo;
import com.chessmaster.Repo.GameEntityRepo;

@Service
public class ChessService {

    @Autowired
    private StateRepo stateRepo;
    @Autowired
    private GameEntityRepo gameRepo;

    public Boolean makeMove(String gameId, int or, int oc, int nr, int nc, Board board,User user, String turn) {

        if(user.getColor().equals(turn)){
            // check if the move is valid
            Piece piece = board.getPiece(or, oc);
            if(piece==null || !piece.getColor().equals(user.getColor())){
                return false;
            }
            else{

                if(nr < 0 || nr > 7 || nc < 0 || nc > 7 || (nr == or && nc == oc)) {
                    return false;
                }
                
                if(!piece.validMove(or, oc, nr, nc, board, user)) {
                    return false;
                }
                
            }
        }
        else{
            return false;
        }


        Piece oldPiece = board.getPiece(or, oc);
        Piece newPiece = board.getPiece(nr, nc);

        if(newPiece!=null &&  newPiece.getName().equals("king")) {
            return false;
        }
        else if(newPiece==null){
            if(oldPiece.getName().equals("pawn")){
                if(oldPiece.getColor().equals("white") && nr==7) {
                    oldPiece.setName("queen");
                }
                else if(oldPiece.getColor().equals("black") && nr==0) {
                    oldPiece.setName("queen");
                }
            }
            BoolResponse res= isSafe(board.getBoard());
            board.setPiece(nr, nc, oldPiece);
            if(res.getRes()==false && res.getPieceColor().equals(user.getColor()) && user.getColor().equals(turn)) {
                // white in check and its white turn
                
                res = isSafe(board.getBoard());
                if(!res.getRes()) {
                    board.setPiece(or, oc, oldPiece); // revert the move
                    board.setPiece(nr, nc, newPiece);
                    return false; 
                }    
            }

            else{ res = isSafe(board.getBoard());
                if(!res.getRes() && res.getPieceColor().equals(oldPiece.getColor())) {
                    board.setPiece(or, oc, oldPiece); // revert the move
                    board.setPiece(nr, nc, newPiece);
                    return false; 
                }
            }
            GameData gd = gameRepo.findByGameId(gameId)
                .orElseThrow(() -> new RuntimeException("Game not found"));
            this.stateRepo.save(new State(oldPiece.getName(), or, nr, oc, nc, oldPiece.getColor(),gd));
        }
        // newPiece is not null 
        else{
            if(oldPiece.getName().equals("paw4n")){
                if(oldPiece.getColor().equals("white") && nr==7) {
                    oldPiece.setName("queen");
                }
                else if(oldPiece.getColor().equals("black") && nr==0) {
                    oldPiece.setName("queen");
                }
            }
            BoolResponse res= isSafe(board.getBoard());
            board.setPiece(nr, nc, oldPiece);
            if(res.getRes()==false && res.getPieceColor().equals(turn) && user.getColor().equals(turn)) {
                // white in check and its white turn
                res = isSafe(board.getBoard());
                if(!res.getRes()) {
                    board.setPiece(or, oc, oldPiece); // revert the move
                    board.setPiece(nr, nc, newPiece);
                    return false; 
                }    
            }

            else{res = isSafe(board.getBoard());
                if(!res.getRes() && res.getPieceColor().equals(oldPiece.getColor())) {
                    board.setPiece(or, oc, oldPiece); // revert the move
                    board.setPiece(nr, nc, newPiece);
                    return false; 
                }
            }
            GameData gd = gameRepo.findByGameId(gameId)
                .orElseThrow(() -> new RuntimeException("Game not found"));

            this.stateRepo.save(new State(oldPiece.getName(),or, oc,nr, nc, oldPiece.getColor(),gd));
            this.stateRepo.save(new State(newPiece.getName(),nr,nc, -1, -1, newPiece.getColor(),gd));
        }
        
        return true;
    }

    

    // Working
    public BoolResponse isSafe(Piece [][] currBoard) {

        for(int i=0;i<8;i++){
            for(int j=0;j<8;j++){
                Piece piece=currBoard[i][j];
                if(piece!=null && piece.getName().equals("king") && piece.getColor().equals("black")){
                    
                    BoolResponse mainRes=checkBlackKing(i, j, currBoard);
                    if(mainRes.getRes()){
                        mainRes.setRes(false);
                        return mainRes; // black king is in check
                    }
                }
                else if( piece!=null && piece.getName().equals("king") && piece.getColor().equals("white")){
                    BoolResponse mainRes=checkWhiteKing(i,j, currBoard);
                    if(mainRes.getRes()){
                        mainRes.setRes(false);
                        return mainRes; // white king is in check
                    }
                }
            }
        }
        
        
        BoolResponse res=new BoolResponse();
        res.setPieceColor("none");
        res.setRes(true); // no king is in check
        return res;
    }
 
    // Working
    private BoolResponse checkWhiteKing(int i,int j,Piece[][] currBoard){
        // 5x5 matrix pawns and knight
        for(int strow=i-2;strow<=i+2;strow++){
            for(int stcol=j-2;stcol<=j+2;stcol++){
                if(strow<0 || strow>7 || stcol<0 || stcol>7) {
                    continue;
                }
                Piece checkPiece=currBoard[strow][stcol];
                if(checkPiece!=null) {
                    if(strow==i+1 && ( stcol==j-1 || stcol==j+1) ){
                        if(checkPiece.getName().equals("pawn") && checkPiece.getColor().equals("black")){
                            BoolResponse res=new BoolResponse();
                            res.setPieceColor("white");
                            res.setRes(true);
                            res.setRow(i);
                            res.setCol(j);
                            res.setFromRow(strow);
                            res.setFromCol(stcol);
                            return res; 
                        }
                    }
                    if((Math.abs(strow-i)==1 && Math.abs(stcol-j)==2) || (Math.abs(strow-i)==2 && Math.abs(stcol-j)==1)){
                        if(checkPiece.getName().equals("knight") && checkPiece.getColor().equals("black")){
                            
                            BoolResponse res=new BoolResponse();
                            res.setPieceColor("white");
                            res.setRes(true);
                            res.setRow(i);
                            res.setCol(j);
                            res.setFromRow(strow);
                            res.setFromCol(stcol);
                            return res; 
                        }
                    }
                }   
            }
        }
        
        // check in up down right left
        // left
        for(int k=j-1;k>=0;k--){
            Piece checkPiece=currBoard[i][k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("rook") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("black")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("white");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i);
                    res.setFromCol(k);
                    return res; 
                }
                break;
            }
        }
        // right
        for(int k=j+1;k<8;k++){
            Piece checkPiece=currBoard[i][k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("rook") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("black")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("white");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i);
                    res.setFromCol(k);
                    return res;
                }
                break;
            }
        }
        // up
        for(int k=i-1;k>=0;k--){
            Piece checkPiece=currBoard[k][j];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("rook") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("black")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("white");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(k);
                    res.setFromCol(j);
                    return res;
                }
                break;
            }
        }
        // down
        for(int k=i+1;k<8;k++){
            Piece checkPiece=currBoard[k][j];
            if(checkPiece!=null ){
                if(checkPiece.getName().equals("rook") || checkPiece.getName().equals("queen") && checkPiece.getColor().equals("black")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("white");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(k);
                    res.setFromCol(j);
                    return res;
                }
                break;
            }
        }
        
        
        // check in cross up down right left
        // up left
        for(int k=1;k<8;k++){
            if(i-k<0 || j-k<0) {
                break;
            }
            Piece checkPiece=currBoard[i-k][j-k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("bishop") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("black")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("white");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i-k);
                    res.setFromCol(j-k);
                    return res;
                }
                break;
            }
        }
        // up right
        for(int k=1;k<8;k++){
            if(i-k<0 || j+k>7) {
                break;
            }
            Piece checkPiece=currBoard[i-k][j+k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("bishop") || checkPiece.getName().equals("queen") )&& checkPiece.getColor().equals("black")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("white");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i-k);
                    res.setFromCol(j+k);
                    return res;
                }
                break;
            }
        }
        // down left
        for(int k=1;k<8;k++){
            if(i+k>7 || j-k<0) {
                break;
            }
            Piece checkPiece=currBoard[i+k][j-k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("bishop") || checkPiece.getName().equals("queen") )&& checkPiece.getColor().equals("black")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("white");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i+k);
                    res.setFromCol(j-k);
                    return res;
                }
                break;
            }
        }

        // down right
        for(int k=1;k<8;k++){
            if(i+k>7 || j+k>7) {
                break;
            }
            Piece checkPiece=currBoard[i+k][j+k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("bishop") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("black")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("white");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i+k);
                    res.setFromCol(j+k);
                    return res;
                }
                break;
            }
        }
        BoolResponse res=new BoolResponse();
        res.setPieceColor("white");
        res.setRes(false); // white king is safe
        return res;

    }
    
    // Working 
    private BoolResponse checkBlackKing(int i, int j, Piece[][] currBoard) {
        // 5x5 matrix pawns and knight
        for(int strow=i-2;strow<=i+2;strow++){
            for(int stcol=j-2;stcol<=j+2;stcol++){
                if(strow<0 || strow>7 || stcol<0 || stcol>7) {
                    continue;
                }
                Piece checkPiece=currBoard[strow][stcol];
                if(checkPiece!=null) {
                    if(strow==i-1 &&  (stcol==j-1 || stcol==j+1) ){
                        if((checkPiece.getName().equals("pawn") || checkPiece.getName().equals("bishop")) && checkPiece.getColor().equals("white")){
                            BoolResponse res=new BoolResponse();
                            res.setPieceColor("black");
                            res.setRes(true);
                            res.setRow(i);
                            res.setCol(j);
                            res.setFromRow(strow);
                            res.setFromCol(stcol);
                            return res;
                        }
                    }
                    if((Math.abs(strow-i)==1 && Math.abs(stcol-j)==2) || (Math.abs(strow-i)==2 && Math.abs(stcol-j)==1)){
                        if(checkPiece.getName().equals("knight") && checkPiece.getColor().equals("white")){
                            BoolResponse res=new BoolResponse();
                            res.setPieceColor("black");
                            res.setRes(true);
                            res.setRow(i);
                            res.setCol(j);
                            res.setFromRow(strow);
                            res.setFromCol(stcol);
                            return res; // black king is in check
                        }
                    }  
                }
            }
        }
        
        // check in up down right left
        // left
        for(int k=j-1;k>=0;k--){
            Piece checkPiece=currBoard[i][k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("rook") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("white")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("black");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i);
                    res.setFromCol(k);
                    return res; // black king is in check
                }
                break;
            }
        }
        // right
        for(int k=j+1;k<8;k++){
            Piece checkPiece=currBoard[i][k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("rook") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("white")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("black");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i);
                    res.setFromCol(k);
                    return res; // black king is in check
                }
                break;
            }
        }
        // up
        for(int k=i-1;k>=0;k--){
            Piece checkPiece=currBoard[k][j];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("rook") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("white")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("black");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(k);
                    res.setFromCol(j);
                    return res; // black king is in check
                }
                break;
            }
        }
        // down
        for(int k=i+1;k<8;k++){
            Piece checkPiece=currBoard[k][j];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("rook") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("white")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("black");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(k);
                    res.setFromCol(j);
                    return res; // black king is in check
                }
                break;
            }
        }
        
        
        // check in cross up down right left
        // up left
        for(int k=1;k<8;k++){
            if(i-k<0 || j-k<0) {
                break;
            }
            Piece checkPiece=currBoard[i-k][j-k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("bishop") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("white")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("black");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i-k);
                    res.setFromCol(j-k);
                    return res; // black king is in check
                }
                break;
            }
        }
        // up right
        for(int k=1;k<8;k++){
            if(i-k<0 || j+k>7) {
                break;
            }
            Piece checkPiece=currBoard[i-k][j+k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("bishop") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("white")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("black");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i-k);
                    res.setFromCol(j+k);
                    return res; // black king is in check
                }
                break;
            }
        }
        // down left
        for(int k=1;k<8;k++){
            if(i+k>7 || j-k<0) {
                break;
            }
            Piece checkPiece=currBoard[i+k][j-k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("bishop") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("white")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("black");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i+k);
                    res.setFromCol(j-k);
                    return res; // black king is in check
                }
                break;
            }
        }

        // down right
        for(int k=1;k<8;k++){
            if(i+k>7 || j+k>7) {
                break;
            }
            Piece checkPiece=currBoard[i+k][j+k];
            if(checkPiece!=null ){
                if((checkPiece.getName().equals("bishop") || checkPiece.getName().equals("queen")) && checkPiece.getColor().equals("white")){
                    BoolResponse res=new BoolResponse();
                    res.setPieceColor("black");
                    res.setRes(true);
                    res.setRow(i);
                    res.setCol(j);
                    res.setFromRow(i+k);
                    res.setFromCol(j+k);
                    return res; // black king is in check

                }
                break;
            }
        }
    BoolResponse res=new BoolResponse();
        res.setPieceColor("black");
        res.setRes(false); // black king is safe
        return res;
}

//    Working
    public BoolResponse isWin(Board board,User user1,User user2){
        // Board tpBoard = new Board(board);
        Board tpBoard = board;
        BoolResponse res = isSafe(tpBoard.getBoard());
        // king is in check
        if(!res.getRes()){
            int row = res.getRow();
            int col = res.getCol();

            // king piece
            Piece oldPiece = board.getPiece(row, col);
            
            // check for all pieces if possible to move to remove check
            Piece checkFromPiece=tpBoard.getPiece(res.getFromRow(), res.getFromCol());
            
            for(int i=0;i<8;i++){
                for(int j=0;j<8;j++){
                    Piece piece=tpBoard.getPiece(i, j);
                    if(piece==null || piece.getColor().equals(checkFromPiece.getColor())){
                        continue;
                    }
                        
                    if(checkFromPiece.getName().equals("queen") || checkFromPiece.getName().equals("bishop")){
                        // movement is diagonal
                        if(checkFromPiece.getRow()<row && col<checkFromPiece.getCol()){
                            // top right
                            for(int k=1;k<8;k++){
                            if(row-k<0 || col+k>7 || (row-k==checkFromPiece.getRow() && col+k==checkFromPiece.getCol())) {
                                break;
                            }
                            
                            User tpUser;
                            if(piece.getColor().equals("white")){
                                tpUser=user1;
                            }
                            else{
                                tpUser=user2;
                            }
                            // currnt position is i-k and j+k
                            Boolean ck1=piece.validMove(piece.getRow(),piece.getCol(),row-k,col+k,board,tpUser);
                            
                            if(ck1){
                                tpBoard.setPiece(row-k,col+k,piece);
                                BoolResponse currRes = isSafe(tpBoard.getBoard());
                                if(currRes.getRes()){
                                    // check can be removed by this move
                                    tpBoard.setPiece(i,j,piece);
                                    BoolResponse bs=new BoolResponse();
                                    bs.setPieceColor("removed by placing in top right");
                                    bs.setRes(false);
                                    return bs;
                                }
                                else{
                                    // revert changes
                                    tpBoard.setPiece(i,j,piece);
                                }
                            }
                        }
                        
                        }

                        else if(checkFromPiece.getRow()<row && checkFromPiece.getCol()<col){
                                // top left
                            for(int k=1;k<8;k++){
                                if(row-k<0 || col-k<0 || (row-k==checkFromPiece.getRow() && col-k==checkFromPiece.getCol())) {
                                    break;
                                }
                                // currnt position is i-k and j-k
                                
                                User tpUser;
                                if(piece.getColor().equals("white")){
                                    tpUser=user1;
                                }
                                else{
                                    tpUser=user2;
                                }
                                // currnt position is i-k and j+k
                                Boolean ck=piece.validMove(piece.getRow(),piece.getCol(),row-k,col-k,board,tpUser);

                                
                                if(ck){
                                    tpBoard.setPiece(row-k,col-k,piece);
                                    BoolResponse currRes = isSafe(tpBoard.getBoard());
                                    if(currRes.getRes()){
                                        // check can be removed by this move
                                        tpBoard.setPiece(i,j,piece);
                                        BoolResponse bs=new BoolResponse();
                                        bs.setPieceColor("removed by placing in top left");
                                        bs.setRes(false);
                                        return bs;
                                    }
                                    else{
                                        // revert changes
                                        tpBoard.setPiece(i,j,piece);
                                    }
                                }
                            }

                        }
                            
                        else if(checkFromPiece.getRow()>row && checkFromPiece.getCol()>col){
                            // bottom right
                            for(int k=1;k<8;k++){
                                if(row+k>7 || col+k>7 || (row+k==checkFromPiece.getRow() && col+k==checkFromPiece.getCol())) {
                                    break;
                                }
                                // currnt position is i+k and j+k
                                
                                User tpUser;
                                if(piece.getColor().equals("white")){
                                    tpUser=user1;
                                }
                                else{
                                    tpUser=user2;
                                }
                                // currnt position is i-k and j+k
                                Boolean ck=piece.validMove(piece.getRow(),piece.getCol(),row+k,col+k,board,tpUser);

                                
                                if(ck){
                                    tpBoard.setPiece(row+k,col+k,piece);
                                    BoolResponse currRes = isSafe(tpBoard.getBoard());
                                    if(currRes.getRes()){
                                        // check can be removed by this move
                                        tpBoard.setPiece(i,j,piece);
                                        BoolResponse bs=new BoolResponse();
                                        bs.setPieceColor("removed by placing in bottom right");
                                        bs.setRes(false);
                                        return bs;
                                    }
                                    else{
                                        // revert changes
                                        tpBoard.setPiece(i,j,piece);
                                    }
                                }
                            }

                        }
                        
                        else if(checkFromPiece.getRow()>row && checkFromPiece.getCol()<col){
                            // bottom left
                            for(int k=1;k<8;k++){
                                if(row+k>7 || col-k<0 || (row+k==checkFromPiece.getRow() && col-k==checkFromPiece.getCol())) {
                                    break;
                                }
                                // currnt position is i+k and j-k
                                
                                User tpUser;
                                if(piece.getColor().equals("white")){
                                    tpUser=user1;
                                }
                                else{
                                    tpUser=user2;
                                }
                                // currnt position is i-k and j+k
                                Boolean ck=piece.validMove(piece.getRow(),piece.getCol(),row+k,col-k,board,tpUser);

                                
                                if(ck){
                                    tpBoard.setPiece(row+k,col-k,piece);
                                    BoolResponse currRes = isSafe(tpBoard.getBoard());
                                    if(currRes.getRes()){
                                        // check can be removed by this move
                                        tpBoard.setPiece(i,j,piece);
                                        BoolResponse bs=new BoolResponse();
                                        bs.setPieceColor("removed by placing in bottom left");
                                        bs.setRes(false);
                                        return bs;
                                    }
                                    else{
                                        // revert changes
                                        tpBoard.setPiece(i,j,piece);
                                    }
                                }
                            }

                        }  
                        
                    }
                    if(checkFromPiece.getName().equals("rook") ||  checkFromPiece.getName().equals("queen")){
                        // movement is either up down left right
                        if(row==checkFromPiece.getRow()){
                            if(checkFromPiece.getCol()<col){
                                // left
                                for(int k=col-1;k>=0;k--){
                                    if(row==checkFromPiece.getRow() && k==checkFromPiece.getCol()){
                                        continue;
                                    }

                                    User tpUser;
                                    if(piece.getColor().equals("white")){
                                        tpUser=user1;
                                    }
                                    else{
                                        tpUser=user2;
                                    }
                                    // currnt position is i-k and j+k
                                    Boolean ck=piece.validMove(piece.getRow(),piece.getCol(),row,k,board,tpUser);
                                    
                                    if(ck){
                                        tpBoard.setPiece(row, k, piece);
                                        BoolResponse currRes = isSafe(tpBoard.getBoard());
                                        if(currRes.getRes()){
                                            // check can be removed by this move
                                            tpBoard.setPiece(i,j,piece);
                                            BoolResponse bs=new BoolResponse();
                                            bs.setPieceColor("removed by placing in left");
                                            bs.setRes(false);   
                                            return bs;
                                        }
                                        else{
                                            // revert changes
                                            tpBoard.setPiece(i,j,piece);
                                        }
                                    }

                                }

                            }
                            else{
                                // right
                                for(int k=col+1;k<8;k++){
                                    
                                    if(row==checkFromPiece.getRow() && k==checkFromPiece.getCol()){
                                        continue;
                                    }
                                    
                                    User tpUser;
                                    if(piece.getColor().equals("white")){
                                        tpUser=user1;
                                    }
                                    else{
                                        tpUser=user2;
                                    }
                                    // currnt position is i-k and j+k
                                    Boolean ck=piece.validMove(piece.getRow(),piece.getCol(),row,k,board,tpUser);

                                    if(ck){
                                        tpBoard.setPiece(row, k, piece);
                                        BoolResponse currRes = isSafe(tpBoard.getBoard());
                                        if(currRes.getRes()){
                                            // check can be removed by this move
                                            tpBoard.setPiece(i,j,piece);
                                            BoolResponse bs=new BoolResponse();
                                            bs.setPieceColor("removed by placing in right");
                                            bs.setRes(false);   
                                            return bs;
                                        }
                                        else{
                                            // revert changes
                                            tpBoard.setPiece(i,j,piece);
                                        }
                                    }
                                    
                                }

                            }
                        }
                        else if(col==checkFromPiece.getCol()){
                            if(checkFromPiece.getRow()<row){
                                    // top
                                for(int k=row-1;k>=0;k--){

                                    if(k==checkFromPiece.getRow() && col==checkFromPiece.getCol()){
                                        continue;
                                    }

                                    User tpUser;
                                    if(piece.getColor().equals("white")){
                                        tpUser=user1;
                                    }
                                    else{
                                        tpUser=user2;
                                    }
                                    // currnt position is i-k and j+k
                                    Boolean ck=piece.validMove(piece.getRow(),piece.getCol(),k,col,board,tpUser);

                                    
                                    if(ck){
                                        tpBoard.setPiece(k, col, piece);
                                        BoolResponse currRes = isSafe(tpBoard.getBoard());
                                        if(currRes.getRes()){
                                            // check can be removed by this move
                                            tpBoard.setPiece(i,j,piece);
                                            BoolResponse bs=new BoolResponse();
                                            bs.setPieceColor("removed by placing in top");
                                            bs.setRes(false);   
                                            return bs;
                                        }
                                        else{
                                            // revert changes
                                            tpBoard.setPiece(i,j,piece);
                                        }
                                    }

                                }
                            }
                            else{
                                // bottom
                                for(int k=row+1;k<8;k++){

                                    if(k==checkFromPiece.getRow() && col==checkFromPiece.getCol()){
                                        continue;
                                    }

                                    User tpUser;
                                    if(piece.getColor().equals("white")){
                                        tpUser=user1;
                                    }
                                    else{
                                        tpUser=user2;
                                    }
                                    // currnt position is i-k and j+k
                                    Boolean ck=piece.validMove(piece.getRow(),piece.getCol(),k,col,board,tpUser);

                                    
                                    if(ck){
                                        tpBoard.setPiece(k, col, piece);
                                        BoolResponse currRes = isSafe(tpBoard.getBoard());
                                        if(currRes.getRes()){
                                            // check can be removed by this move
                                            tpBoard.setPiece(i,j,piece);
                                            BoolResponse bs=new BoolResponse();
                                            bs.setPieceColor("removed by placing in bottom");
                                            bs.setRes(false);   
                                            return bs;
                                        }
                                        else{
                                            // revert changes
                                            tpBoard.setPiece(i,j,piece);
                                        }
                                    }

                                }

                            }
                        }
                        }  
                        
                        // check for elementaion of the checkFromPiece
                        // Working fine
                        User tpUser;
                            if(piece.getColor().equals("white")){
                                tpUser=user1;
                            }
                            else{
                                tpUser=user2;
                            }
                        // currnt position is i-k and j+k
                        Boolean moveCheck=piece.validMove(piece.getRow(),piece.getCol(),checkFromPiece.getRow(),checkFromPiece.getCol(),board,tpUser);
                        if(moveCheck){
                            tpBoard.setPiece(checkFromPiece.getRow(), checkFromPiece.getCol(), piece);
                            BoolResponse bs=isSafe(tpBoard.getBoard());
                            if(bs.getRes()){
                                // check can be removed by this move
                                tpBoard.setPiece(i,j,piece);
                                tpBoard.setPiece(res.getFromRow(), res.getFromCol(), checkFromPiece);
                                BoolResponse response=new BoolResponse();
                                response.setPieceColor("removed by elimination from :"+piece.getName()+" at "+piece.getRow()+ "," +piece.getCol());
                                response.setRes(false);
                                return response;
                            }
                            else{
                                // revert changes
                                tpBoard.setPiece(i, j, piece);
                                tpBoard.setPiece(res.getFromRow(), res.getFromCol(), checkFromPiece);
                            }
                        }
                       
                    }
                
                }                    
            // No moves possible its a checkmate
            BoolResponse bs=new BoolResponse();
            if(oldPiece.getColor().equals("white")){
                bs.setPieceColor("black");
            }
            else{
                bs.setPieceColor("white");
            }
            bs.setRes(true);
            return bs;
        }
        BoolResponse bs=new BoolResponse();
        bs.setPieceColor("no check");
        bs.setRes(false);
        return bs;
    }

}
