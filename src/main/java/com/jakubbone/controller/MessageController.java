package com.jakubbone.controller;

import com.jakubbone.dto.SendMessageRequest;
import com.jakubbone.model.Message;
import com.jakubbone.service.MessageService;
import com.jakubbone.utils.ResponseHandler;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/messages")
public class MessageController {
    private final MessageService messageService;

    public MessageController(MessageService messageService) {
        this.messageService = messageService;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> sendMessage(@Valid @RequestBody SendMessageRequest req, Authentication authentication){
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String senderUsername = jwt.getClaimAsString("preferred_username");

        Message savedMessage = messageService.sendMessage(senderUsername, req.getTo(), req.getText());
        return ResponseHandler.success(HttpStatus.CREATED, savedMessage);
    }
}
