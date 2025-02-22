package com.auth.service;

import com.auth.dto.AuthUserRequestDTO;
import com.auth.dto.AuthUserResponseDTO;
import com.auth.dto.UpdateUserDTO;
import com.auth.entity.UserEntity;
import com.auth.exception.UserExistsException;
import com.auth.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.tomcat.websocket.AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
public class UserService {

    private static String LOGIN_INCORRECT = "Usuário/Senha incorreta";

    @Value("${security.token.secret}")
    private String secretKey;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserEntity createUser(UserEntity userEntity) {

        this.userRepository
                .findByUsernameOrEmail(userEntity.getUsername(), userEntity.getEmail())
                .ifPresent((user) -> {
                    throw new UserExistsException();
                });
        userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
        var user = userRepository.save(userEntity);

        return user;
    }

    public AuthUserResponseDTO authenticationUser(AuthUserRequestDTO authUserRequestDTO) throws AuthenticationException {

        var user = this.userRepository.findByUsername(authUserRequestDTO.username())
                .orElseThrow(() -> {
                    throw new UsernameNotFoundException(LOGIN_INCORRECT);
                });

        if (verifyPasswordMatches(authUserRequestDTO.password(), user.getPassword())) {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);

            var expiresIn = Instant.now().plus(Duration.ofMinutes(30));
            var token = JWT.create()
                    .withIssuer(user.getName())
                    .withClaim("id", user.getId().toString())
                    .withExpiresAt(expiresIn)
                    .withSubject(user.getId().toString())
                    .sign(algorithm);

            return AuthUserResponseDTO.builder()
                    .acces_token(token)
                    .expires_in(expiresIn.getEpochSecond())
                    .build();

        } else {
            throw new AuthenticationException(LOGIN_INCORRECT);
        }
    }

    private boolean verifyPasswordMatches(String rawPassword, String password) {

        return this.passwordEncoder.matches(rawPassword, password);
    }

    public UpdateUserDTO updateUser(String token, UpdateUserDTO updateUserDTO) {

        UUID id = this.jwtService.ExtractUUID(token);

        UserEntity userUpdate = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        userUpdate.setName(updateUserDTO.getName());
        userUpdate.setUsername(updateUserDTO.getUsername());
        userUpdate.setEmail(updateUserDTO.getEmail());
        userUpdate.setPassword(passwordEncoder.encode(updateUserDTO.getPassword()));

        userRepository.save(userUpdate);

        return updateUserDTO;
    }

    public Object deleteUser(String token) {

        UUID id = this.jwtService.ExtractUUID(token);

        UserEntity userDeleted = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        this.userRepository.deleteById(id);

        return userDeleted;
    }
}
