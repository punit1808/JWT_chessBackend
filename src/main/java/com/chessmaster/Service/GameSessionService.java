package com.chessmaster.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.chessmaster.Models.Game;
import com.chessmaster.Models.User;
import com.chessmaster.Models.Board;
import com.chessmaster.Models.BoolResponse;
import com.chessmaster.WebSocket.GameSessionManager;

@Service
public class GameSessionService {
    
    @Autowired
    private GameSessionManager gameSessionManager;
    @Autowired
    private ChessService chessService;

    public Boolean addGame(String gameId){
        Game game=new Game(gameId);
        game.setGameId(gameId);
        return this.gameSessionManager.registerGame(game);
    }

    public void setWin(String gameId,BoolResponse bs){
        this.gameSessionManager.setWin(gameId,bs.getPieceColor());
    }

    public Boolean moveService(int or,int oc,int nr,int nc,String gameId,String uniqueId){
        Game currGame=this.gameSessionManager.getGame(gameId);
        if(currGame==null) return false;

        if(this.gameSessionManager.isSpectator(gameId,uniqueId)){
            return false;
        }
        User player1=currGame.getPlayer1Id();
        User player2=currGame.getPlayer2Id();
        if(player1.getUniqueId().equals(uniqueId) && currGame.getTurn().equals(player1.getColor())){
            Boolean ck= this.chessService.makeMove(gameId,or, oc, nr, nc, currGame.getBoard(), player1, currGame.getTurn());
            if(ck){
                currGame.setTurn("black");
                return true;
            }
        }
        if(player2.getUniqueId().equals(uniqueId) && currGame.getTurn().equals(player2.getColor())){
            Boolean ck= this.chessService.makeMove(gameId,or, oc, nr, nc, currGame.getBoard(), player2, currGame.getTurn());
            if(ck){
                currGame.setTurn("white");
                return true;
            }
        }
        return false;
    }

    public Board getBoard(String gameId){
        Game currGame=this.gameSessionManager.getGame(gameId);
        return currGame.getBoard();
    }

    public String getTurn(String gameId){
        Game currGame=this.gameSessionManager.getGame(gameId);
        return currGame.getTurn();
    }

    public BoolResponse checkWin(Board board){
        Game currGame=this.gameSessionManager.getGame(board.getGameId());
        User user1,user2;
        user1=currGame.getPlayer1Id();
        user2=currGame.getPlayer2Id();
        return this.chessService.isWin(board,user1,user2);
    }
}
