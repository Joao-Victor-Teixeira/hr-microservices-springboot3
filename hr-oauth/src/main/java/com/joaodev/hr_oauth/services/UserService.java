package com.joaodev.hr_oauth.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.joaodev.hr_oauth.entities.User;
import com.joaodev.hr_oauth.feignclients.UserFeignClient;

@Service
public class UserService implements UserDetailsService {

    private static Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserFeignClient userFeignClient;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("Procurando utilizador do email: " + username);
        User user = userFeignClient.findByEmail(username).getBody();
        if (user == null) {
            logger.error("Email não encontrado: " + username);
            throw new UsernameNotFoundException("Email não encontrado");
        }
       
        logger.info("Email encontrado: " + username);
        return user;

    }

}
