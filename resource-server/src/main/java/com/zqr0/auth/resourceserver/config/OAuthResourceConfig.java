package com.zqr0.auth.resourceserver.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.io.*;
import java.net.URL;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Scanner;

@Configuration
@EnableWebSecurity
@Slf4j
public class OAuthResourceConfig {

    private final JWSAlgorithm JWS_ALGORITHM = JWSAlgorithm.RS256;
    private final JWEAlgorithm JWE_ALGORITHM = JWEAlgorithm.RSA_OAEP_256;
    private final EncryptionMethod ENCRYPTION_METHOD = EncryptionMethod.A256GCM;

    @Value(value = "${private.key.location}")
    private RSAPrivateKey privateKey;

    @Value(value = "${jwk.set.uri}")
    private URL JWK_SET_URI;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(
                        auth -> auth.anyRequest().authenticated()

                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return new NimbusJwtDecoder(this.jwtProcessor());
    }

    private JWTProcessor<SecurityContext> jwtProcessor() {
        JWKSource<SecurityContext> jwsJwkSource = new RemoteJWKSet<>(this.JWK_SET_URI);
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(this.JWS_ALGORITHM, jwsJwkSource);

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(this.rsaKey()));
        JWEKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(this.JWE_ALGORITHM,
                this.ENCRYPTION_METHOD, jwkSource);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWEKeySelector(jweKeySelector);

        log.info("jwt processor works");

        return jwtProcessor;
    }

    private RSAKey rsaKey() {
        //System.out.println(this.source.toString()); = class path resource

        //final RSAPrivateKey KEY = this.converter.convert(this.source.toString());
        RSAPrivateCrtKey privateCrtKey = (RSAPrivateCrtKey) this.privateKey;

        final Base64URL N = Base64URL.encode(privateCrtKey.getModulus());
        final Base64URL E = Base64URL.encode(privateCrtKey.getPublicExponent());

        return new RSAKey.Builder(N, E)
                .privateKey(privateCrtKey)
                .keyUse(KeyUse.ENCRYPTION)
                .build();
    }
}
