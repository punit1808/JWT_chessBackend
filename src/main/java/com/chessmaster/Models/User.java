package com.chessmaster.Models;
import jakarta.persistence.*;

@Entity
@Table(name = "chess_users")
public class User {
    
    @Id
    private String uniqueId;

    private String name;
    private String userId;
    private String game_id;
   
    private String type; 
    public String getGame_id() {
        return game_id;
    }

    public void setGame_Id(String game_id) {
        this.game_id = game_id;
    }

    private String color;


    public User(){

    }
    
    public User(String game_id,String playerId,String uniqueId){
        this.game_id=game_id;
        this.name = "user";
        this.userId = playerId;
        this.type = "player"; // Default type is player
        this.uniqueId=uniqueId;
        this.color = "none"; 
    }

    public String getUniqueId() {
        return uniqueId;
    }


    public void setUniqueId(String uniqueId) {
        this.uniqueId = uniqueId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUserId() {
        return userId;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    

}
