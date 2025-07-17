package com.chessmaster.WebSocket;

import com.chessmaster.Models.Game;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

@Component
public class GameWebSocketHandler extends TextWebSocketHandler {

    private final GameSessionManager sessionManager;

    public GameWebSocketHandler(GameSessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String gameId = getPathVariable(session, "gameId");
        String playerId = getPathVariable(session, "playerId");
        String uniqueId = getPathVariable(session,"uniqueId");

        // Game must already be registered
        Game game = sessionManager.getGame(gameId);
        if (game == null || !sessionManager.isGame(gameId)) {
            session.close(CloseStatus.BAD_DATA);
            return;
        }

        sessionManager.addPlayer(gameId, playerId, uniqueId, session); // Handles player/spectator logic internally
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String gameId = getPathVariable(session, "gameId");
        String playerId = getPathVariable(session, "playerId");

        String payload = message.getPayload();

    if ("true".equalsIgnoreCase(payload) || "false".equalsIgnoreCase(payload)) {
        // Broadcast just boolean string as-is
        for (WebSocketSession receiver : sessionManager.getReceivers(gameId, playerId)) {
            if (receiver.isOpen()) {
                receiver.sendMessage(new TextMessage(payload));
            }
        }
    } else {
        // Default text message with player prefix
        for (WebSocketSession receiver : sessionManager.getReceivers(gameId, playerId)) {
            if (receiver.isOpen()) {
                receiver.sendMessage(new TextMessage(playerId + ": " + payload));
            }
        }
    }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        String gameId = getPathVariable(session, "gameId");
        String playerId = getPathVariable(session, "playerId");

        sessionManager.removePlayer(gameId, playerId); // Handles both player and spectator cleanup
    }

    private String getPathVariable(WebSocketSession session, String var) {
        // Assuming path format: /ws/game/{gameId}/{playerId}
        String[] parts = session.getUri().getPath().split("/");
        if (parts.length >= 5) {
            return var.equals("gameId") ? parts[3] : parts[4];
        }
        return "";
    }
}
