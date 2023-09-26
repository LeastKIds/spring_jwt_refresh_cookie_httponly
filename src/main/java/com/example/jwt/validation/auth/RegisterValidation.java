package com.example.jwt.validation.auth;


import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.jwt.dto.request.auth.RegisterRequest;
import com.example.jwt.error.ErrorResponse;
import com.example.jwt.repository.auth.UserRepository;
import com.example.jwt.service.auth.AuthenticationService;

public class RegisterValidation {

    private static final Logger logger = LoggerFactory.getLogger(RegisterValidation.class);

    public ErrorResponse registerValidation(RegisterRequest request, UserRepository userRepository) {
        Map<String, String> errors = new HashMap<>();

        if(request.getFirstname() == null || request.getFirstname().length() < 1) {
            errors.put("firstname", "fistname must be at least 1 character long.");
            logger.error(String.format("fistname must be at least 1 character long. \n firstname: %s", request.getFirstname()));
        }
            
        if(request.getLastname() == null || request.getLastname().length() < 1 ) {
            errors.put("lastname", "lastname must be at least 1 character long.");
            logger.error(String.format("lastname must be at least 1 character long. \n lastname: %s", request.getLastname()));
        }
            
        
        if(request.getEmail() != null) {
            String emailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
            Pattern emailPattern = Pattern.compile(emailRegex);
            Matcher emailMatcher = emailPattern.matcher(request.getEmail());
            if(!emailMatcher.matches()) {
                errors.put("email", "Invalid email format.");
                logger.error(String.format("Invalid email format. \n email: %s", request.getEmail()));
            }
                

            if(userRepository.findByEmail(request.getEmail()).isPresent()) {
                errors.put("email_duplicate", "This email already exists.");
                logger.error(String.format("This email already exists. \n email_duplicate: %s", request.getEmail()));
            }
                
        } else {
            errors.put("email", "Invalid email format.");
            logger.error(String.format("Invalid email format. \n email: %s", request.getEmail()));
        }
        

        if(request.getPassword() == null || request.getPassword().length() < 4 || request.getPassword().length() > 20) {
            errors.put("password", "The password must be between 4 and 20 characters long.");
            logger.error(String.format("The password must be between 4 and 20 characters long. \n password: %s", request.getPassword()));
        }
            


        

        return ErrorResponse.builder().errors(errors).build();
    }
}