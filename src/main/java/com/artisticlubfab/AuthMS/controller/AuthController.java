package com.artisticlubfab.AuthMS.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.artisticlubfab.AuthMS.models.User;
import com.artisticlubfab.AuthMS.repository.UserRepository;
import com.artisticlubfab.AuthMS.request.LoginRequest;
import com.artisticlubfab.AuthMS.request.SignupRequest;
import com.artisticlubfab.AuthMS.response.JwtResponse;
import com.artisticlubfab.AuthMS.response.MessageResponse;
import com.artisticlubfab.AuthMS.security.jwt.JwtUtils;
import com.artisticlubfab.AuthMS.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateuser
               (@RequestBody LoginRequest loginRequest) {

        org.springframework.security.core.Authentication authentication = authenticationManager.authenticate
                 (new UsernamePasswordAuthenticationToken
                        (loginRequest.getUsername(), 
                                loginRequest.getPassword()));

        SecurityContextHolder.getContext()
               .setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) 
                              authentication.getPrincipal();

        return ResponseEntity
                .ok(new JwtResponse(jwt, userDetails.getId(),
                   userDetails.getUsername(), 
                            userDetails.getEmail()));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser
                  (@RequestBody SignupRequest signUpRequest) {

        if (userRepository.existsByUsername(signUpRequest
              .getUsername())) {

            return ResponseEntity.badRequest()
                .body(new MessageResponse
                  ("Error: username is already taken!"));
        }

        if (userRepository.existsByEmail
                           (signUpRequest.getEmail())) {

            return ResponseEntity.badRequest()
                 .body(new MessageResponse
                        ("Error: Email is already in use!"));
        }

        // Create new user account
        User user = new User(signUpRequest.getUsername(), 
                           signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        userRepository.save(user);

        return ResponseEntity
         .ok(new MessageResponse("user registered successfully!"));
    }
}