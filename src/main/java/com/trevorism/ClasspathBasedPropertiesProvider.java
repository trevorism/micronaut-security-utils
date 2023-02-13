package com.trevorism;

import java.io.IOException;
import java.util.Properties;

public class ClasspathBasedPropertiesProvider implements PropertiesProvider {
    private final Properties properties = new Properties();
    private final String fileName;
    private boolean loaded;

    public ClasspathBasedPropertiesProvider() {
        this("secrets.properties");
    }

    public ClasspathBasedPropertiesProvider(String fileName) {
        this.fileName = fileName;
        loaded = false;
    }

    @Override
    public String getProperty(String name) {
        lazyLoadProperties();
        return properties.getProperty(name);
    }

    private void lazyLoadProperties() {
        if (!loaded) {
            try {
                properties.load(PropertiesProvider.class.getClassLoader().getResourceAsStream(fileName));
            } catch (IOException ignored) {

            }
            loaded = true;
        }
    }
}
