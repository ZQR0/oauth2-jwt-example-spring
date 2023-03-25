package com.zqr0.auth.resourceserver.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.Scanner;

@Component
@ConfigurationPropertiesBinding
@Slf4j
public class StringToRSAPrivateConverter implements Converter<String, RSAPrivateKey> {

    private static final ResourceLoader resourceLoader = new DefaultResourceLoader();

    @Override
    public RSAPrivateKey convert(String source) {
        try(InputStream is = resourceLoader.getResource(source).getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(is);
        } catch (IOException ex) {
            log.info("IO Exception handled");
            throw new IllegalStateException(ex);
        }
    }
}
