package com.tigerit.elasticexample.api;

import com.tigerit.elasticexample.auth.JWT;
import com.tigerit.elasticexample.auth.JWTAuthorizationFilter;
import com.tigerit.elasticexample.model.User;
import com.tigerit.elasticexample.model.UserResponse;
import com.tigerit.elasticexample.model.UserResponse;
import com.tigerit.elasticexample.model.request.AuthRequest;
import com.tigerit.elasticexample.model.response.AuthResponse;

import com.tigerit.elasticexample.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.*;

import static com.tigerit.elasticexample.auth.SecurityConstants.*;


@RestController
@RequestMapping(path = "/rest/auth")
//@ApiResponses(value = {
//        @ApiResponse(responseCode = "200", description = "Success"),
//        @ApiResponse(responseCode = "400", description = "Bad Request"),
//        @ApiResponse(responseCode = "401", description = "You are not authorized to view the resource"),
//        @ApiResponse(responseCode = "403", description = "Accessing the resource you were trying to reach is forbidden"),
//        @ApiResponse(responseCode = "404", description = "The resource you were trying to reach is not found"),
//        @ApiResponse(responseCode = "500", description = "Internal Server Error")
//})
public class AuthController {

    private static Logger logger =  LoggerFactory.getLogger(AuthController.class);
    private final MessageSource messageSource;
    private AuthenticationManager authenticationManager;
    private JWT jwt;
    private UserService userService;

    public AuthController(AuthenticationManager authenticationManager,
                          JWT jwt,
                          MessageSource messageSource,
                          UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwt = jwt;
        this.messageSource = messageSource;
        this.userService = userService;

    }

    @RequestMapping(path = "/login", method = RequestMethod.POST)
    public Object login(@RequestBody AuthRequest authRequest, Locale locale) {
        System.out.println("Inside /auth/login with with username "+ authRequest.getUsername());
        authRequest.setUsername(authRequest.getUsername().trim().toLowerCase());
        try {
            String username = authRequest.getUsername();
            User user = userService.findByUsername(username);
            if(!user.getPassword().equals(authRequest.getPassword())){
                return new IllegalAccessException("Wrong Password");
            }


//            User user;
//            if (optionalUser.isPresent()) {
//                user = optionalUser.get();
//                logger.debug("User : {}", user.toString());
//                logger.debug("User Status: {}", user.getStatus().toString());
//                if (user.getStatus().equals(Status.INACTIVE)) {
//                    logger.debug("User Status is Inactive, throwing disabled exception");
//                    throw new DisabledException("User is INACTIVE");
//                }
//                methodAccessList = userRepository.findMethodAccessListByUsername(user.getUsername());
//            } else {
//                throw new UserNotFoundException("User Not Found");
//            }

            Date tokenCreateTime = new Date();

            String accessToken = jwt.createToken(username, ACCESS_TOKEN);


            logger.debug("White list -> Access Token Key : {}", accessToken);

            UserResponse userResponse = new UserResponse(username,user.getFirstName(),user.getLastName(),accessToken);

            return userResponse;
        } catch (Exception ex) {
            return ex;
        }
    }

    @RequestMapping(path = "/register", method = RequestMethod.POST)
    public Object register(@RequestBody AuthRequest authRequest, Locale locale) {
        System.out.println("Inside /auth/register with with username "+ authRequest.getUsername());
        authRequest.setUsername(authRequest.getUsername().trim().toLowerCase());
        try {
            String username = authRequest.getUsername();
            logger.debug("Authentication Start");
//            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, authRequest.getPassword()));
            logger.debug("Authentication Complete");
//            Optional<User> optionalUser = userRepository.findByUsername(username);
//            User user;
//            if (optionalUser.isPresent()) {
//                user = optionalUser.get();
//                logger.debug("User : {}", user.toString());
//                logger.debug("User Status: {}", user.getStatus().toString());
//                if (user.getStatus().equals(Status.INACTIVE)) {
//                    logger.debug("User Status is Inactive, throwing disabled exception");
//                    throw new DisabledException("User is INACTIVE");
//                }
//                methodAccessList = userRepository.findMethodAccessListByUsername(user.getUsername());
//            } else {
//                throw new UserNotFoundException("User Not Found");
//            }

            Date tokenCreateTime = new Date();

            String accessToken = jwt.createToken(username, ACCESS_TOKEN);


            logger.debug("White list -> Access Token Key : {}", accessToken);

            return new UserResponse(username,username,"",accessToken);
        } catch (Exception ex) {
            return ex;
        }
    }


//    @RequestMapping(path = "/logout", method = RequestMethod.POST)
//    @Operation(summary = "Logout",
//            security = @SecurityRequirement(name = "bearer-auth"),
//            description = "Need to Provide Bearer Token In Authorization Header")
//    public ResponseEntity<RestApiResponse<String>> logout(HttpServletRequest request, Locale locale) {
//        logger.debug("Inside /auth/logout for logout of AuthController");
//        UserDetails userDetails = (UserDetails) request.getSession().getAttribute(SessionKey.USER_DETAILS);
//        String tokenType = (String) request.getSession().getAttribute(SessionKey.TYPE_OF_TOKEN);
//        logger.debug("username : {} and tokenType from session : {}", userDetails.getUsername(), tokenType);
//        RestApiResponse<String> restApiResponse;
//        boolean inserted = jwt.insertTokenToBlackList(request, tokenType);
//        if (inserted) {
//            logger.debug("Logout Operation Success, Returning Response");
//            restApiResponse = Utils.buildSuccessRestResponse(HttpStatus.OK, ResponseMessages.LOGOUT_SUCCESS);
//            return ResponseEntity.status(restApiResponse.getStatus()).body(restApiResponse);
//        } else {
//            logger.debug("Logout Operation Failed, Returning Response");
//            restApiResponse = Utils.buildErrorRestResponse(HttpStatus.INTERNAL_SERVER_ERROR,
//                    messageSource.getMessage("field.logout", null, locale), ResponseMessages.LOGOUT_FAILED);
//            return ResponseEntity.status(restApiResponse.getStatus()).body(restApiResponse);
//        }
//    }
}