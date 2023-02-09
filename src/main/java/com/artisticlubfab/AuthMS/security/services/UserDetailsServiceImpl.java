package com.artisticlubfab.AuthMS.security.services;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.artisticlubfab.AuthMS.models.User;
import com.artisticlubfab.AuthMS.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) 
                       throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() 
                     -> new UsernameNotFoundException
             ("user Not Found with username: " + username));

        return UserDetailsImpl.build(user);
    }
}