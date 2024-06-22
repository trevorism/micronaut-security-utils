package com.trevorism.micronaut;

import com.trevorism.ClasspathBasedPropertiesProvider;
import com.trevorism.PropertiesProvider;
import jakarta.inject.Singleton;

@Singleton
public class PropertiesBean implements PropertiesProvider {

    private final PropertiesProvider propertiesProvider = new ClasspathBasedPropertiesProvider();

    public String getProperty(String prop){
        return propertiesProvider.getProperty(prop);
    }
}
