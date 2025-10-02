package com.bsep.pki.config;

import jakarta.annotation.PostConstruct;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.io.File;

@Component
public class LogDirectoryInitializer {

    private static final Logger log = LogManager.getLogger(LogDirectoryInitializer.class);

    @PostConstruct
    public void ensureLogDirectoryExists() {
        File dir = new File("logs");
        if (!dir.exists()) {
            boolean created = dir.mkdirs();
            if (created) {
                log.info("Created logs directory at {}", dir.getAbsolutePath());
            } else {
                log.warn("Failed to create logs directory at {}", dir.getAbsolutePath());
            }
        }
    }
}


