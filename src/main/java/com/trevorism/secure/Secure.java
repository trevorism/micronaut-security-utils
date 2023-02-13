package com.trevorism.secure;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author tbrooks
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Secure {

    String value() default "";

    /** When true, a token must be generated specifically for this app, by making the audience match this app's clientId **/
    boolean authorizeAudience() default false;
    /** When true, long-lived tokens internal to trevorism are authorized to call the endpoint */
    boolean allowInternal() default false;
}